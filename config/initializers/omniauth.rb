# frozen_string_literal: true

OmniAuth.config.allowed_request_methods = %i[post]
OmniAuth.config.silence_get_warning = true
OmniAuth.config.logger = Rails.logger

Rails.application.config.middleware.use OmniAuth::Builder do # rubocop:disable Metrics/BlockLength
  provider :openid_connect,
           name: :oidc,
           setup: lambda { |env| # rubocop:disable Metrics/BlockLength
             req = Rack::Request.new(env)

             account_uuid = req.POST['account_uuid'].presence ||
                            env.dig('rack.session', 'oauth_account_uuid').presence

             account = if account_uuid
                         Account.find_by(uuid: account_uuid)
                       elsif !Docuseal.multitenant?
                         Account.first
                       end

             next unless account

             config = EncryptedConfig.find_by(account: account, key: EncryptedConfig::OAUTH_CONFIGS_KEY)&.value

             next if config.blank?

             env['rack.session']['oauth_account_uuid'] = account.uuid

             strategy = env['omniauth.strategy']
             strategy.options[:issuer]        = config['issuer']
             strategy.options[:discovery]     = config.fetch('discovery', true)
             strategy.options[:scope]         = config.fetch('scope', %w[openid email profile]).map(&:to_sym)
             strategy.options[:uid_field]     = (config['uid_field'] || 'sub').to_sym
             strategy.options[:response_type] = :code
             strategy.options[:pkce]          = true
             strategy.options[:client_options].identifier = config['client_id']
             strategy.options[:client_options].secret     = config['client_secret']
             url_options = Docuseal.default_url_options
             strategy.options[:client_options].redirect_uri =
               URI::Generic.build(scheme: url_options[:protocol] || 'http',
                                  host: url_options[:host],
                                  port: url_options[:port],
                                  path: '/auth/oidc/callback').to_s
           }
end
