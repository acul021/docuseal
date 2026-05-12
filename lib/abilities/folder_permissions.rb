# frozen_string_literal: true

module Abilities
  # Resolves a user's effective role on each folder in their account.
  # Admin team members short-circuit to 'editor' on every folder.
  module FolderPermissions
    Resolver = Struct.new(:user, :grants_by_folder, keyword_init: true) do
      def admin?
        @admin ||= user.admin?
      end

      def role_on(folder_or_id)
        folder_id = folder_or_id.is_a?(TemplateFolder) ? folder_or_id.id : folder_or_id
        return TeamFolderPermission::EDITOR if admin?

        grants_by_folder[folder_id]
      end

      def editor?(folder_or_id)
        role_on(folder_or_id) == TeamFolderPermission::EDITOR
      end

      def viewer_or_better?(folder_or_id)
        TeamFolderPermission::ROLES.include?(role_on(folder_or_id))
      end

      def accessible_folder_ids(min_role: TeamFolderPermission::VIEWER)
        return :all if admin?

        min_rank = TeamFolderPermission::ROLE_RANK.fetch(min_role)
        grants_by_folder.each_with_object([]) do |(id, role), acc|
          acc << id if TeamFolderPermission::ROLE_RANK[role] >= min_rank
        end
      end
    end

    module_function

    def for(user)
      return Resolver.new(user: user, grants_by_folder: {}) if user.admin?

      grants = TeamFolderPermission
               .where(team_id: user.team_ids)
               .pluck(:template_folder_id, :role)

      collapsed = grants.each_with_object({}) do |(folder_id, role), acc|
        acc[folder_id] = TeamFolderPermission.higher(acc[folder_id], role)
      end

      Resolver.new(user: user, grants_by_folder: collapsed)
    end
  end
end
