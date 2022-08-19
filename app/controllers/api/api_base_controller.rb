class Api::ApiBaseController < ApplicationController
  include ApiKeyAuthenticatable

  MFA_INVALID_MSG = 'second factor must be valid'.freeze
  OTP_INVALID_MSG = 'one time password is invalid'.freeze
  OTP_REQUIRED_MSG = 'one time password is required'.freeze
  PWD_INVALID_MSG = 'password must be valid'.freeze

  def mfa_invalid
    raise(
      UnauthorizedRequestError.new(
        message: MFA_INVALID_MSG,
        code: 'MFA_INVALID'
      )
    )
  end

  def otp_invalid
    raise(
      UnauthorizedRequestError.new(
        message: OTP_INVALID_MSG,
        code: 'OTP_INVALID'
      )
    )
  end

  def otp_required
    raise(
      UnauthorizedRequestError.new(
        message: OTP_REQUIRED_MSG,
        code: 'OTP_REQUIRED'
      )
    )
  end

  def password_invalid
    raise(
      UnauthorizedRequestError.new(
        message: PWD_INVALID_MSG,
        code: 'PWD_INVALID'
      )
    )
  end

  rescue_from ActiveRecord::RecordInvalid, with: -> { render status: :unprocessable_entity }
  rescue_from ActiveRecord::RecordNotUnique, with: -> { render status: :conflict }
  rescue_from ActiveRecord::RecordNotFound, with: -> { render status: :not_found }

  rescue_from UnauthorizedRequestError do |e|
    error = { message: e.message, code: e.code }

    render json: { error: error }, status: :unauthorized
  end
end
