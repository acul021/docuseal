# frozen_string_literal: true

class SsoSettingsController < ApplicationController
  before_action :load_encrypted_config

  authorize_resource :encrypted_config, only: :index
  authorize_resource :encrypted_config, parent: false, only: :create

  def index; end

  def create
    if @encrypted_config.update(encrypted_config_params)
      redirect_to settings_sso_index_path, notice: I18n.t('changes_have_been_saved')
    else
      render :index, status: :unprocessable_content
    end
  rescue StandardError => e
    flash[:alert] = e.message
    render :index, status: :unprocessable_content
  end

  def destroy
    @encrypted_config.destroy!
    redirect_to settings_sso_index_path, notice: I18n.t('changes_have_been_saved')
  end

  private

  def load_encrypted_config
    @encrypted_config =
      EncryptedConfig.find_or_initialize_by(account: current_account, key: EncryptedConfig::OAUTH_CONFIGS_KEY)
  end

  def encrypted_config_params
    params.require(:encrypted_config).permit(value: {}).tap do |p|
      value = p[:value] || {}

      # Parse comma-separated email domains into an array
      if value['email_domains'].is_a?(String)
        value['email_domains'] = value['email_domains'].split(/[\s,]+/).map(&:strip).compact_blank
      end

      # Parse space/comma-separated scope into an array of strings
      if value['scope'].is_a?(String)
        value['scope'] = value['scope'].split(/[\s,]+/).map(&:strip).compact_blank
      end

      # Keep existing client_secret if the field was left blank
      if value['client_secret'].blank? && @encrypted_config.value.is_a?(Hash)
        value['client_secret'] = @encrypted_config.value['client_secret']
      end

      value.compact_blank!
      p[:value] = value
    end
  end
end
