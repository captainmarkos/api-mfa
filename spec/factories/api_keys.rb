FactoryBot.define do
  factory :api_key do
    token_digest { SecureRandom.hex }

    transient do
     bearer { create(:user) }
    end

    bearer_id { bearer.id }
    bearer_type { bearer.class.name }
  end
end
