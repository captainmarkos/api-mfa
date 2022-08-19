class Api::V1::SecondFactorsController < Api::ApiBaseController
  prepend_before_action :authenticate_with_api_key!

  def index; end

  def show; end

  def create
    second_factor = current_bearer.second_factors.new

    # Verify second factor if enabled, otherwise verify password.
    if current_bearer.second_factor_enabled?
      result = current_bearer.authenticate_with_second_factor(otp: params[:otp])
      mfa_invalid if result.blank?
    else
      result = current_bearer.authenticate(params[:password])
      password_invalid if result.blank?
    end

    second_factor.save!

    render json: second_factor, status: :created
  end

  def update
    second_factor = current_bearer.second_factors.find(params[:id])

    # Verify this particular 2nd factor (which may not be enabled yet).
    otp_invalid unless second_factor.verify_with_otp(params[:otp])

    second_factor.update!(enabled: params[:enabled])

    render json: second_factor, status: :ok
  end

  def destroy; end
end
