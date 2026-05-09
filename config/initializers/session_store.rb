# frozen_string_literal: true

Rails.application.config.session_store :cookie_store,
                                       key: '_docuseal_session',
                                       expire_after: ENV.fetch('SESSION_EXPIRE_HOURS', '3').to_f.hours
