class Api::V1::SecondFactorsController < Api::ApiBaseController
  include ApiKeyAuthenticatable

  MFA_INVALID_MSG = 'second factor must be valid'
  PWD_INVALID_MSG = 'password must be valid'

  prepend_before_action :authenticate_with_api_key!

  def index; end

  def show; end

  def create
    second_factor = current_bearer.second_factors.new

    # Verify second factor if enabled, otherwise verify password.
    if current_bearer.second_factor_enabled?
      result = current_bearer.authenticate_with_second_factor(otp: params[:otp])
      raise(
          UnauthorizedRequestError,
          message: MFA_INVALID_MSG,
          code: 'MFA_INVALID'
      ) unless result.present?
    else
      result = current_bearer.authenticate(params[:password])
      raise(
        UnauthorizedRequestError,
        message: PWD_INVALID_MSG,
        code: 'PWD_INVALID'
      ) if result.blank?
    end

    second_factor.save!

    render json: second_factor, status: :created
  end

  def update; end

  def destroy; end
end
