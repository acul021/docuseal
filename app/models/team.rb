# frozen_string_literal: true

# == Schema Information
#
# Table name: teams
#
#  id         :bigint           not null, primary key
#  is_admin   :boolean          default(FALSE), not null
#  name       :string           not null
#  created_at :datetime         not null
#  updated_at :datetime         not null
#  account_id :bigint           not null
#
class Team < ApplicationRecord
  DEFAULT_ADMIN_NAME = 'Admins'

  belongs_to :account

  has_many :team_memberships, dependent: :destroy
  has_many :users, through: :team_memberships
  has_many :team_folder_permissions, dependent: :destroy
  has_many :template_folders, through: :team_folder_permissions

  scope :admin, -> { where(is_admin: true) }
  scope :regular, -> { where(is_admin: false) }

  validates :name, presence: true
  validates :name, uniqueness: { scope: :account_id, case_sensitive: false }

  def self.find_or_create_by_name(account, name, attrs = {})
    existing = where(account: account).where('lower(name) = ?', name.to_s.downcase).first
    existing || create!({ account: account, name: name }.merge(attrs))
  end
end
