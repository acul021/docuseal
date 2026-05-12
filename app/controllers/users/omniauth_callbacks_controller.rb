# frozen_string_literal: true

module Users
  class OmniauthCallbacksController < Devise::OmniauthCallbacksController
    def oidc
      auth    = request.env['omniauth.auth']
      account = resolve_account

      return redirect_to new_user_session_path, alert: I18n.t('sso_configuration_not_found') unless account

      email  = auth.info.email.to_s.strip.downcase
      config = oauth_config_for(account)

      unless email_domain_allowed?(email, config)
        return redirect_to new_user_session_path, alert: I18n.t('sso_email_domain_not_allowed')
      end

      identity = UserOauthIdentity.find_by(provider: auth.provider, uid: auth.uid)
      user     = identity&.user || User.find_by(email: email, account: account)

      team_names = team_names_from_claims(auth, config)
      user = sync_sso_user(user, account, email, auth)
      sync_sso_teams(user, account, team_names, config)

      unless user.active_for_authentication?
        return redirect_to new_user_session_path, alert: I18n.t('your_account_is_locked')
      end

      unless identity
        UserOauthIdentity.create!(
          user: user,
          provider: auth.provider,
          uid: auth.uid,
          email: email,
          raw_info: auth.extra&.raw_info.to_h
        )
      end

      sign_in_and_redirect user, event: :authentication
    ensure
      session.delete(:oauth_account_uuid)
    end

    def failure
      Rollbar.warning("SSO failure: #{failure_message}") if defined?(Rollbar)
      redirect_to new_user_session_path, alert: I18n.t('sso_authentication_failed')
    end

    private

    def resolve_account
      uuid = session[:oauth_account_uuid].presence
      if uuid
        Account.find_by(uuid: uuid)
      elsif !Docuseal.multitenant?
        Account.first
      end
    end

    def oauth_config_for(account)
      EncryptedConfig.find_by(account: account, key: EncryptedConfig::OAUTH_CONFIGS_KEY)&.value
    end

    def provision_sso_user(account, email, auth)
      first_name, last_name = names_from_auth(auth)

      account.users.create!(
        email: email,
        first_name: first_name,
        last_name: last_name,
        password: SecureRandom.hex(32),
        confirmed_at: Time.current
      )
    end

    def sync_sso_user(user, account, email, auth)
      return provision_sso_user(account, email, auth) unless user

      attrs = {}
      first_name, last_name = names_from_auth(auth)
      attrs[:first_name] = first_name if first_name.present? && user.first_name != first_name
      attrs[:last_name]  = last_name  if last_name.present?  && user.last_name  != last_name

      user.update(attrs) if attrs.any?
      user
    end

    def sync_sso_teams(user, account, team_names, config)
      return if team_names.nil? # no team_attribute configured — leave memberships alone

      auto_create = ActiveModel::Type::Boolean.new.cast(config&.dig('auto_create_teams'))

      resolved_teams = team_names.filter_map do |name|
        existing = account.teams.where('lower(name) = ?', name.downcase).first
        next existing if existing
        next nil unless auto_create

        account.teams.create!(name: name, is_admin: false)
      end

      target_ids = resolved_teams.to_set(&:id)
      current_ids = user.team_ids.to_set

      # Guard: never strip the last admin user out of every admin team.
      removable_team_ids = (current_ids - target_ids).to_a
      removable_team_ids = filter_out_orphaning_admin_removal(user, account, removable_team_ids)

      TeamMembership.where(user_id: user.id, team_id: removable_team_ids).delete_all if removable_team_ids.any?

      (target_ids - current_ids).each do |team_id|
        TeamMembership.find_or_create_by!(user_id: user.id, team_id: team_id)
      end

      unknown = team_names - resolved_teams.map(&:name)
      Rails.logger.info("[SSO] skipped unknown teams for #{user.email}: #{unknown.inspect}") if unknown.any?
    end

    def filter_out_orphaning_admin_removal(user, account, candidate_team_ids)
      return candidate_team_ids if candidate_team_ids.empty?

      admin_team_ids = account.teams.where(id: candidate_team_ids, is_admin: true).pluck(:id)
      return candidate_team_ids if admin_team_ids.empty?

      other_admin_user_count = TeamMembership
                               .joins(:team)
                               .where(teams: { account_id: account.id, is_admin: true })
                               .where.not(user_id: user.id)
                               .distinct
                               .count(:user_id)

      if other_admin_user_count.zero?
        Rails.logger.warn(
          "[SSO] refused to remove #{user.email} from admin team(s) #{admin_team_ids.inspect} " \
          '— would orphan the account'
        )
        candidate_team_ids - admin_team_ids
      else
        candidate_team_ids
      end
    end

    def names_from_auth(auth)
      first = auth.info.first_name.to_s.strip
      last  = auth.info.last_name.to_s.strip
      return [first, last] if first.present? && last.present?

      full = auth.info.name.to_s.strip
      full = "#{first} #{last}".strip if full.blank?
      parts = full.split(/\s+/, 2)
      [parts.first.to_s, parts.last.to_s == parts.first.to_s ? '' : parts.last.to_s]
    end

    def team_names_from_claims(auth, config)
      attribute = config&.dig('team_attribute').to_s.strip
      return nil if attribute.blank?

      raw_info = auth.extra&.raw_info.to_h
      value = raw_info[attribute] || auth.info[attribute]
      return [] if value.blank?

      Array(value).flat_map { |v| v.to_s.split(/[\s,]+/) }.map(&:strip).compact_blank.uniq
    end

    def email_domain_allowed?(email, config)
      allowed_domains = config&.dig('email_domains').presence
      return true unless allowed_domains

      allowed_domains.any? { |domain| email.end_with?("@#{domain}") }
    end

    def failure_message
      request.env['omniauth.error']&.message || 'unknown error'
    end
  end
end
