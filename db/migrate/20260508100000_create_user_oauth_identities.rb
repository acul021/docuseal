# frozen_string_literal: true

class CreateUserOauthIdentities < ActiveRecord::Migration[8.0]
  def change
    create_table :user_oauth_identities do |t|
      t.references :user, null: false, foreign_key: true
      t.string :provider, null: false
      t.string :uid, null: false
      t.string :email
      t.text :raw_info, default: '{}'
      t.timestamps
    end

    add_index :user_oauth_identities, %i[provider uid], unique: true
  end
end
