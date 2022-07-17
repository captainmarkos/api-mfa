FactoryBot.define do
  factory :user do
    email { Faker::Internet.email }
    password { 'topsecret' }

    trait :with_api_keys do
      after(:create) do |u|
        u.api_keys.create!(token: SecureRandom.hex)
      end
    end
  end
end
