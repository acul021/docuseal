# frozen_string_literal: true

FactoryBot.define do
  factory :user do
    account
    first_name { Faker::Name.first_name }
    last_name { Faker::Name.last_name }
    password { 'password' }
    email { Faker::Internet.email }

    # Existing test suites assume the user is an admin. Add them to the
    # account's admin team by default (creating it if necessary). Use the
    # :member trait to opt out.
    after(:create) do |user|
      team = user.account.teams.where(is_admin: true).first ||
             user.account.teams.create!(name: Team::DEFAULT_ADMIN_NAME, is_admin: true)
      team.users << user unless team.users.exists?(id: user.id)
    end

    trait :member do
      after(:create) { |user| user.team_memberships.destroy_all }
    end

    trait :integration do
      role { User::INTEGRATION_ROLE }
      after(:create) { |user| user.team_memberships.destroy_all }
    end
  end
end
