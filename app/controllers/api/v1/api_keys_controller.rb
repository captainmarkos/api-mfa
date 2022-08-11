class Api::V1::ApiKeysController < Api::ApiBaseController
  include ApiKeyAuthenticatable

  # Require API key authentication
  prepend_before_action :authenticate_with_api_key!, only: [:index, :destroy]

  def index
    render json: current_bearer.api_keys
  end

  def create
    authenticate_with_http_basic do |email, password|
      user = User.find_by(email: email)

      # Request or verify the user's 2nd factor if enabled.
      if user&.second_factor_enabled?
        otp = params[:otp]
        second_factor_missing if otp.blank?

        verified = user.authenticate_with_second_factor(otp: otp)
        second_factor_invalid unless verified
      end

      if user&.authenticate(password)
        api_key = user.api_keys.create!(token: SecureRandom.hex)
        render json: api_key, status: :created and return
      end
    end

    render status: :unauthorized
  end

  def destroy
    api_key = current_bearer.api_keys.find(params[:id])

    api_key.destroy
    render json: {
      status: 'success',
      message: "deleted id #{params[:id]}",
    }
  rescue ActiveRecord::RecordNotFound => e
    render json: {
      status: "failed to delete id #{params[:id]}",
      message: "#{e.message}"
    }
  end

  private

  def second_factor_missing
    raise(
      UnauthorizedRequestError,
      message: 'second factor is required',
      code 'OTP_REQUIRED'
    )
  end

  def second_factor_invalid
    raise(
      UnauthorizedRequestError,
      message: 'second factor is invalid',
      code: 'OTP_INVALID'
    )
  end
end
