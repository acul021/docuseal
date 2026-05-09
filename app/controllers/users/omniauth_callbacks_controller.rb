# frozen_string_literal: true

module Users
  class OmniauthCallbacksController < Devise::OmniauthCallbacksController
    ROLE_CLAIM_MAP = {
      'admin' => User::ADMIN_ROLE,
      'editor' => User::EDITOR_ROLE,
      'writer' => User::EDITOR_ROLE,
      'viewer' => User::VIEWER_ROLE
    }.freeze

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

      user = sync_sso_user(user, account, email, auth, role_from_claims(auth, config))

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

    def provision_sso_user(account, email, auth, mapped_role = nil)
      first_name, last_name = names_from_auth(auth)

      account.users.create!(
        email: email,
        first_name: first_name,
        last_name: last_name,
        role: mapped_role || User::VIEWER_ROLE,
        password: SecureRandom.hex(32),
        confirmed_at: Time.current
      )
    end

    def sync_sso_user(user, account, email, auth, mapped_role)
      return provision_sso_user(account, email, auth, mapped_role) unless user

      attrs = {}
      attrs[:role] = mapped_role if mapped_role && user.role != mapped_role

      first_name, last_name = names_from_auth(auth)
      attrs[:first_name] = first_name if first_name.present? && user.first_name != first_name
      attrs[:last_name]  = last_name  if last_name.present?  && user.last_name  != last_name

      user.update(attrs) if attrs.any?
      user
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

    def role_from_claims(auth, config)
      attribute = config&.dig('role_attribute').to_s.strip
      return nil if attribute.blank?

      raw_info = auth.extra&.raw_info.to_h
      value = raw_info[attribute] || auth.info[attribute]
      return nil if value.blank?

      values = Array(value).flat_map { |v| v.to_s.downcase.split(/[\s,]+/) }
      values.lazy.filter_map { |v| ROLE_CLAIM_MAP[v] }.first
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
