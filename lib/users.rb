# frozen_string_literal: true

module Users
  module_function

  def generate_csv(users)
    headers = %w[email first_name last_name teams current_sign_in_at last_sign_in_at updated_at created_at]

    CSVSafe.generate do |csv|
      csv << headers

      users.each do |user|
        row = headers.map do |h|
          h == 'teams' ? user.teams.map(&:name).join(';') : user.public_send(h)
        end
        csv << row
      end
    end
  end
end
