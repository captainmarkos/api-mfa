class User < ApplicationRecord
  has_many :api_keys, as: :bearer, dependent: :destroy
  has_many :second_factors

  has_secure_password

  def second_factor_enabled?
    second_factors.enabled.any?
  end

  def authenticate_with_second_factor(otp:)
    return false unless second_factor_enabled?

    # We only allow a single 2FA key right now but we may allow more later,
    # e.g. multiple 2FA keys, backup codes or U2F.
    second_factor = second_factors.enabled.first

    second_factor.verify_with_otp(otp)
  end
end
