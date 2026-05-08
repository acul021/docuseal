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

      return redirect_to new_user_session_path, alert: I18n.t('sso_user_not_found') unless user

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
