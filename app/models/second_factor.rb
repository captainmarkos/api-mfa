class SecondFactor < ApplicationRecord
  OTP_ISSUER = 'Roger Rabbit'

  belongs_to :user

  before_create :generate_otp_secret

  validates :user, presence: true

  scope :enabled, -> { where(enabled: true) }

  def verify_with_otp(otp)
    # Time-based One Time Password
    totp = ROTP::TOTP.new(otp_secret, issuer: OTP_ISSUER)

    totp.verify(otp.to_s)
  end

  private

  def generate_otp_secret
    self.otp_secret = ROTP::Base32.random
  end
end
