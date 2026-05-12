# frozen_string_literal: true

class TeamsMembersController < ApplicationController
  before_action :load_team

  def create
    authorize!(:manage, @team)

    user = current_account.users.find(params.require(:user_id))
    TeamMembership.find_or_create_by!(team: @team, user: user)

    redirect_to settings_team_path(@team), notice: I18n.t('changes_have_been_saved')
  end

  def destroy
    authorize!(:manage, @team)

    if last_admin_user?
      return redirect_to settings_team_path(@team), alert: I18n.t('at_least_one_admin_required')
    end

    TeamMembership.where(team_id: @team.id, user_id: params.require(:id)).destroy_all
    redirect_to settings_team_path(@team), notice: I18n.t('changes_have_been_saved')
  end

  private

  def load_team
    @team = current_account.teams.find(params[:team_id])
  end

  def last_admin_user?
    return false unless @team.is_admin?

    user_id = params[:id].to_i
    other_admin_count = TeamMembership.joins(:team)
                                      .where(teams: { account_id: current_account.id, is_admin: true })
                                      .where.not(user_id: user_id)
                                      .distinct.count(:user_id)
    other_admin_count.zero?
  end
end
