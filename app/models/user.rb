class User < ApplicationRecord
  has_many :api_keys, as: :bearer, dependent: :destroy

  has_secure_password
end
