# frozen_string_literal: true

class TeamsFolderPermissionsController < ApplicationController
  before_action :load_team

  def create
    upsert
  end

  def update
    upsert
  end

  def destroy
    TeamFolderPermission.where(team_id: @team.id, template_folder_id: params.require(:id)).destroy_all
    redirect_to settings_team_path(@team), notice: I18n.t('changes_have_been_saved')
  end

  private

  def load_team
    @team = current_account.teams.find(params[:team_id])
    authorize!(:manage, @team)
  end

  def upsert
    folder = current_account.template_folders.find(params.require(:team_folder_permission)[:template_folder_id])
    role = params.require(:team_folder_permission)[:role].to_s

    if TeamFolderPermission::ROLES.include?(role)
      record = TeamFolderPermission.find_or_initialize_by(team_id: @team.id, template_folder_id: folder.id)
      record.role = role
      record.save!
    else
      TeamFolderPermission.where(team_id: @team.id, template_folder_id: folder.id).destroy_all
    end

    redirect_to settings_team_path(@team), notice: I18n.t('changes_have_been_saved')
  end
end
