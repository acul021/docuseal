# frozen_string_literal: true

class Ability
  include CanCan::Ability

  def initialize(user)
    can :manage, EncryptedUserConfig, user_id: user.id
    can :manage, UserConfig, user_id: user.id
    can :manage, AccessToken, user_id: user.id
    can :manage, McpToken, user_id: user.id
    can :manage, :mcp
    can %i[read update], User, id: user.id

    if user.admin?
      admin_abilities(user)
    else
      member_abilities(user)
    end
  end

  private

  def admin_abilities(user)
    can %i[read create update], Template, Abilities::TemplateConditions.collection(user) do |template|
      Abilities::TemplateConditions.entity(template, user:, ability: 'manage')
    end

    can :destroy, Template, account_id: user.account_id
    can :manage, TemplateFolder, account_id: user.account_id
    can :manage, TemplateSharing, template: { account_id: user.account_id }
    can :manage, Submission, account_id: user.account_id
    can :manage, Submitter, account_id: user.account_id
    can :manage, User, account_id: user.account_id
    can :manage, Team, account_id: user.account_id
    can :manage, TeamMembership, team: { account_id: user.account_id }
    can :manage, TeamFolderPermission, team: { account_id: user.account_id }
    can :manage, EncryptedConfig, account_id: user.account_id
    can :manage, AccountConfig, account_id: user.account_id
    can :manage, Account, id: user.account_id
    can :manage, WebhookUrl, account_id: user.account_id
  end

  def member_abilities(user)
    resolver = Abilities::FolderPermissions.for(user)
    viewer_folder_ids = resolver.accessible_folder_ids(min_role: TeamFolderPermission::VIEWER)
    editor_folder_ids = resolver.accessible_folder_ids(min_role: TeamFolderPermission::EDITOR)

    # Templates: viewer-or-better grants read; editor grants update; editor + author grants destroy.
    can :read, Template,
        Abilities::TemplateConditions.collection(user).where(folder_id: viewer_folder_ids) do |template|
      viewer_folder_ids.include?(template.folder_id) &&
        Abilities::TemplateConditions.entity(template, user:, ability: 'read')
    end

    can %i[create update], Template,
        Abilities::TemplateConditions.collection(user).where(folder_id: editor_folder_ids) do |template|
      editor_folder_ids.include?(template.folder_id) &&
        Abilities::TemplateConditions.entity(template, user:, ability: 'manage')
    end

    can :destroy, Template, account_id: user.account_id, author_id: user.id, folder_id: editor_folder_ids

    # Folder listing — only folders the user has a direct grant on. Non-admins
    # cannot create / rename / delete folders.
    can :read, TemplateFolder, account_id: user.account_id, id: viewer_folder_ids

    # Submissions / submitters track template visibility.
    can :read, Submission, account_id: user.account_id, template: { folder_id: viewer_folder_ids }
    can %i[create update destroy], Submission,
        account_id: user.account_id, template: { folder_id: editor_folder_ids }
    can :read, Submitter, account_id: user.account_id, submission: { template: { folder_id: viewer_folder_ids } }
    can %i[create update], Submitter,
        account_id: user.account_id, submission: { template: { folder_id: editor_folder_ids } }

    can :read, User, account_id: user.account_id
    can :read, Account, id: user.account_id
  end
end
