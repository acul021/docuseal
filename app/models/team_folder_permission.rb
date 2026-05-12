# frozen_string_literal: true

# == Schema Information
#
# Table name: team_folder_permissions
#
#  id                  :bigint           not null, primary key
#  role                :string           not null
#  created_at          :datetime         not null
#  updated_at          :datetime         not null
#  team_id             :bigint           not null
#  template_folder_id  :bigint           not null
#
class TeamFolderPermission < ApplicationRecord
  VIEWER = 'viewer'
  EDITOR = 'editor'
  ROLES = [VIEWER, EDITOR].freeze
  ROLE_RANK = { VIEWER => 1, EDITOR => 2 }.freeze

  belongs_to :team
  belongs_to :template_folder

  validates :role, inclusion: { in: ROLES }
  validates :team_id, uniqueness: { scope: :template_folder_id }

  def self.higher(a, b)
    return a if b.nil?
    return b if a.nil?

    ROLE_RANK[a] >= ROLE_RANK[b] ? a : b
  end
end
