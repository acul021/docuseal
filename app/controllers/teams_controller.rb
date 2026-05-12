# frozen_string_literal: true

class TeamsController < ApplicationController
  load_and_authorize_resource :team

  before_action :scope_team_to_current_account, only: %i[show edit update destroy]
  before_action :assign_current_account, only: %i[new create]

  def index
    @teams = current_account.teams.order(is_admin: :desc, name: :asc)
                            .includes(:users, team_folder_permissions: :template_folder)
  end

  def show
    @available_users = current_account.users.active.where.not(role: User::INTEGRATION_ROLE).order(:email)
    @available_folders = current_account.template_folders.order(:name)
  end

  def new; end

  def edit; end

  def create
    if @team.save
      redirect_to settings_team_path(@team), notice: I18n.t('changes_have_been_saved')
    else
      render :new, status: :unprocessable_content
    end
  end

  def update
    if @team.update(team_params)
      redirect_to settings_team_path(@team), notice: I18n.t('changes_have_been_saved')
    else
      render :edit, status: :unprocessable_content
    end
  end

  def destroy
    if last_admin_team?
      redirect_to settings_teams_path, alert: I18n.t('at_least_one_admin_required')
    else
      @team.destroy!
      redirect_to settings_teams_path, notice: I18n.t('changes_have_been_saved')
    end
  end

  private

  def scope_team_to_current_account
    raise CanCan::AccessDenied unless @team.account_id == current_account.id
  end

  def assign_current_account
    @team.account = current_account
  end

  def team_params
    params.require(:team).permit(:name, :is_admin)
  end

  def last_admin_team?
    return false unless @team.is_admin?

    current_account.teams.admin.where.not(id: @team.id).none?
  end
end
