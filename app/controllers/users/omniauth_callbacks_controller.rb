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

      mapped_role = role_from_claims(auth, config)

      if user
        user.update(role: mapped_role) if mapped_role && user.role != mapped_role
      else
        user = provision_sso_user(account, email, auth, mapped_role)
      end

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
      first_name = auth.info.first_name.presence || auth.info.name.to_s.split(' ', 2).first
      last_name  = auth.info.last_name.presence  || auth.info.name.to_s.split(' ', 2).last

      account.users.create!(
        email: email,
        first_name: first_name,
        last_name: last_name,
        role: mapped_role || User::VIEWER_ROLE,
        password: SecureRandom.hex(32),
        confirmed_at: Time.current
      )
    end

    ROLE_CLAIM_MAP = {
      'admin'  => User::ADMIN_ROLE,
      'editor' => User::EDITOR_ROLE,
      'writer' => User::EDITOR_ROLE,
      'viewer' => User::VIEWER_ROLE
    }.freeze

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
