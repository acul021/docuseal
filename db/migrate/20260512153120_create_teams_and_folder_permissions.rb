# frozen_string_literal: true

class CreateTeamsAndFolderPermissions < ActiveRecord::Migration[7.1]
  class MigrationAccount < ActiveRecord::Base
    self.table_name = 'accounts'
  end

  class MigrationUser < ActiveRecord::Base
    self.table_name = 'users'
  end

  class MigrationTeam < ActiveRecord::Base
    self.table_name = 'teams'
  end

  class MigrationTeamMembership < ActiveRecord::Base
    self.table_name = 'team_memberships'
  end

  def up
    create_table :teams do |t|
      t.references :account, null: false, foreign_key: true, index: true
      t.string :name, null: false
      t.boolean :is_admin, null: false, default: false

      t.timestamps
    end
    add_index :teams, 'account_id, lower(name)', unique: true, name: 'index_teams_on_account_id_and_lower_name'

    create_table :team_memberships do |t|
      t.references :team, null: false, foreign_key: true, index: true
      t.references :user, null: false, foreign_key: true, index: true

      t.timestamps
    end
    add_index :team_memberships, %i[team_id user_id], unique: true

    create_table :team_folder_permissions do |t|
      t.references :team, null: false, foreign_key: true, index: true
      t.references :template_folder, null: false, foreign_key: true, index: true
      t.string :role, null: false

      t.timestamps
    end
    add_index :team_folder_permissions, %i[team_id template_folder_id],
              unique: true,
              name: 'index_team_folder_permissions_on_team_and_folder'

    backfill_admin_teams!

    change_column_null :users, :role, true
  end

  def down
    change_column_null :users, :role, false, 'viewer'

    drop_table :team_folder_permissions
    drop_table :team_memberships
    drop_table :teams
  end

  private

  def backfill_admin_teams!
    now = Time.current

    MigrationAccount.find_each do |account|
      admin_user_ids = MigrationUser.where(account_id: account.id, role: 'admin').pluck(:id)
      next if admin_user_ids.empty?

      team_id = MigrationTeam.create!(
        account_id: account.id,
        name: 'Admins',
        is_admin: true,
        created_at: now,
        updated_at: now
      ).id

      rows = admin_user_ids.map do |user_id|
        { team_id: team_id, user_id: user_id, created_at: now, updated_at: now }
      end
      MigrationTeamMembership.insert_all(rows)
    end

    # Roles 'admin', 'editor', 'viewer' no longer drive authorization. Clear them
    # so future reads of users.role only return 'integration' / 'superadmin' / nil.
    MigrationUser.where(role: %w[admin editor viewer]).update_all(role: nil)
  end
end
