# frozen_string_literal: true

class UsersController < ApplicationController
  load_and_authorize_resource :user, only: %i[index edit update destroy]

  before_action :build_user, only: %i[new create]
  authorize_resource :user, only: %i[new create]

  def index
    @users =
      if params[:status] == 'archived'
        @users.archived.where.not(role: User::INTEGRATION_ROLE)
      elsif params[:status] == 'integration'
        @users.active.where(role: User::INTEGRATION_ROLE)
      else
        @users.active.where.not(role: User::INTEGRATION_ROLE).or(@users.active.where(role: nil))
      end

    @users = @users.preload(:teams, account: :account_accesses)
                   .where(account: current_account).order(id: :desc)

    respond_to do |format|
      format.html do
        @pagy, @users = pagy(@users)
      end

      if current_ability.can?(:manage, current_account)
        format.csv do
          send_data Users.generate_csv(@users), filename: "users-#{Time.current.iso8601}.csv", type: 'text/csv'
        end
      end
    end
  end

  def new; end

  def edit; end

  def create
    existing_user = User.accessible_by(current_ability).find_by(email: @user.email)

    if existing_user
      if existing_user.archived_at? &&
         current_ability.can?(:manage, existing_user) && current_ability.can?(:manage, @user.account)
        existing_user.assign_attributes(@user.slice(:first_name, :last_name, :account_id))
        existing_user.archived_at = nil
        @user = existing_user
      else
        @user.errors.add(:email, I18n.t('already_exists'))

        return render turbo_stream: turbo_stream.replace(:modal, template: 'users/new'), status: :unprocessable_content
      end
    end

    @user.password = SecureRandom.hex if @user.password.blank?
    apply_team_ids(@user, params.dig(:user, :team_ids))

    if @user.save
      UserMailer.invitation_email(@user).deliver_later!

      redirect_back fallback_location: settings_users_path, notice: I18n.t('user_has_been_invited')
    else
      render turbo_stream: turbo_stream.replace(:modal, template: 'users/new'), status: :unprocessable_content
    end
  end

  def update
    return redirect_to settings_users_path, notice: I18n.t('unable_to_update_user') if Docuseal.demo?

    attrs = user_params.compact_blank
    attrs = attrs.merge(user_params.slice(:archived_at)) if current_ability.can?(:create, @user)

    reassign_account_if_requested
    return render_with_error(:edit) unless sync_team_ids_if_requested

    excluded = current_user == @user ? %i[password otp_required_for_login] : %i[password]
    if @user.update(attrs.except(*excluded))
      if @user.try(:pending_reconfirmation?) && @user.previous_changes.key?(:unconfirmed_email)
        SendConfirmationInstructionsJob.perform_async('user_id' => @user.id)

        redirect_back fallback_location: settings_users_path,
                      notice: I18n.t('a_confirmation_email_has_been_sent_to_the_new_email_address')
      else
        redirect_back fallback_location: settings_users_path, notice: I18n.t('user_has_been_updated')
      end
    else
      render turbo_stream: turbo_stream.replace(:modal, template: 'users/edit'), status: :unprocessable_content
    end
  end

  def destroy
    if Docuseal.demo? || @user.id == current_user.id
      return redirect_to settings_users_path, notice: I18n.t('unable_to_remove_user')
    end

    return redirect_to settings_users_path, alert: I18n.t('at_least_one_admin_required') if last_admin_user?(@user)

    @user.update!(archived_at: Time.current)

    redirect_back fallback_location: settings_users_path, notice: I18n.t('user_has_been_removed')
  end

  private

  def reassign_account_if_requested
    return if params.dig(:user, :account_id).blank?

    account = Account.accessible_by(current_ability).find(params.dig(:user, :account_id))
    authorize!(:manage, account)
    @user.account = account
  end

  def sync_team_ids_if_requested
    requested = params.dig(:user, :team_ids)
    return true if requested.nil?
    return true unless current_ability.can?(:manage, @user)
    return true if current_user == @user

    apply_team_ids(@user, requested)
  end

  def build_user
    @user = current_account.users.new(user_params)
  end

  def user_params
    if params.key?(:user)
      params.require(:user).permit(:email, :first_name, :last_name, :password,
                                   :archived_at, :otp_required_for_login)
    else
      {}
    end
  end

  # Returns false (and adds an error to @user) if applying these ids would
  # orphan the account by emptying every admin team.
  def apply_team_ids(user, raw_ids)
    ids = Array(raw_ids).map(&:to_s).compact_blank.map(&:to_i).uniq
    accessible_team_ids = current_account.teams.where(id: ids).pluck(:id)

    if user.persisted? && would_orphan_admin?(user, accessible_team_ids)
      user.errors.add(:base, I18n.t('at_least_one_admin_required'))
      return false
    end

    user.team_ids = accessible_team_ids
    true
  end

  def would_orphan_admin?(user, new_team_ids)
    return false unless user.account_id == current_account.id

    admin_team_ids = current_account.teams.admin.pluck(:id)
    return false if admin_team_ids.empty?
    return false if new_team_ids.intersect?(admin_team_ids) # user keeps an admin team

    other_admins = TeamMembership.joins(:team)
                                 .where(teams: { account_id: current_account.id, is_admin: true })
                                 .where.not(user_id: user.id)
                                 .distinct.count(:user_id)
    other_admins.zero?
  end

  def last_admin_user?(user)
    would_orphan_admin?(user, [])
  end

  def render_with_error(template)
    render turbo_stream: turbo_stream.replace(:modal, template: "users/#{template}"),
           status: :unprocessable_content
  end
end
