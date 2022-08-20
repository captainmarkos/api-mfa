require 'rails_helper'

RSpec.describe SecondFactor, type: :model do
  describe 'associations' do
    it { is_expected.to belong_to(:user) }
  end

  describe 'validations' do
    it { is_expected.to validate_presence_of :user }
  end

  describe '#before_create' do
    let(:second_factor) { create(:second_factor) }

    it 'otp secret is generated as base32 random string' do
      expect(second_factor.otp_secret.length).to eq 32
    end
  end

  describe '#provisioning_uri' do
    context 'when auth factor method is not enabled' do
      let(:auth_method) { create(:second_factor) }

      it 'returns a provisioning uri' do
        expect(auth_method.provisioning_uri).not_to be_nil
      end
    end

    context 'when auth factor method is enabled' do
      let(:auth_method) { create(:second_factor, enabled: true) }

      it 'returns nil' do
        expect(auth_method.provisioning_uri).to be_nil
      end
    end
  end

  describe '#verify_with_otp' do
    context 'when one-time-password is valid' do
      let(:auth_method) { create(:second_factor) }
      let(:totp) { ROTP::TOTP.new(auth_method.otp_secret) }
      let(:password) { totp.now }

      it 'return a timestamp' do
        timestamp = auth_method.verify_with_otp(password)
        expect(timestamp).not_to be_nil
        expect(Time.at(timestamp)).to eq auth_method.otp_verified_at
      end
    end

    context 'when one-time-password is invalid' do
      let(:auth_method) { create(:second_factor) }

      it 'return a timestamp' do
        timestamp = auth_method.verify_with_otp('badpassword')
        expect(timestamp).to be_nil
        expect(auth_method.otp_verified_at).to be_nil
      end
      
    end
  end
end
