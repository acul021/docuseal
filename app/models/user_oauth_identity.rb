# frozen_string_literal: true

# == Schema Information
#
# Table name: user_oauth_identities
#
#  id         :bigint           not null, primary key
#  email      :string
#  provider   :string           not null
#  raw_info   :text             default("{}")
#  uid        :string           not null
#  created_at :datetime         not null
#  updated_at :datetime         not null
#  user_id    :bigint           not null
#
# Indexes
#
#  index_user_oauth_identities_on_provider_and_uid  (provider, uid) UNIQUE
#  index_user_oauth_identities_on_user_id           (user_id)
#
# Foreign Keys
#
#  fk_rails_...  (user_id => users.id)
#
class UserOauthIdentity < ApplicationRecord
  belongs_to :user

  serialize :raw_info, coder: JSON
end
