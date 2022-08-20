FactoryBot.define do
  factory :second_factor do
    enabled { false }
    otp_verified_at { nil }

    transient do
      user { create(:user) }
    end

    user_id { user.id }
  end
end
