# frozen_string_literal: true

# == Schema Information
#
# Table name: team_memberships
#
#  id         :bigint           not null, primary key
#  created_at :datetime         not null
#  updated_at :datetime         not null
#  team_id    :bigint           not null
#  user_id    :bigint           not null
#
class TeamMembership < ApplicationRecord
  belongs_to :team
  belongs_to :user

  validates :user_id, uniqueness: { scope: :team_id }
end
