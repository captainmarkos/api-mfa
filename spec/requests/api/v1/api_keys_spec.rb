require 'rails_helper'

RSpec.describe 'Api::V1::ApiKeys', type: :request do
  before { stub_const 'ENV', ENV.to_h.merge('API_KEY_HMAC_SECRET_KEY' => 'secret-key') }

  describe 'GET /api/v1/api-keys' do
    context 'with bearer authentication' do
      context 'when missing token' do
        it 'not authorized' do
          get '/api/v1/api-keys', headers: { 'Authorization' => "Bearer " }
          expect(response).to have_http_status(:unauthorized) # 401
        end
      end

      context 'with valid token' do
        let(:headers) { { 'Authorization' => "Bearer #{api_key.token}" } }
        let(:admin_user) { create(:user, :with_api_keys) }
        let(:api_key) { admin_user.api_keys.first }

        it 'list bearer API keys' do
          expect(admin_user.api_keys.length).to eq 1
          get '/api/v1/api-keys', headers: headers

          expect(response).to have_http_status(:ok) # 200

          json = JSON.parse(response.body)
          expect(json.length).to eq admin_user.api_keys.length
          expect(json.dig(0, 'bearer_id')).to eq admin_user.id
          expect(json.dig(0, 'bearer_type')).to eq admin_user.class.name
          expect(json.dig(0, 'token')).to be nil
        end
      end
    end
  end

  describe 'POST /api/v1/api-keys' do
    context 'with basic authentication' do
      let(:user) { create(:user, :with_api_keys) }
      let(:headers) { { 'Authorization' => "Basic #{encoded}" } }

      context 'when bad user name' do
        let(:encoded) { Base64.encode64("#{user.email}-fail:#{user.password}") }

        it 'not authorized' do
          post '/api/v1/api-keys', headers: headers
          expect(response).to have_http_status(:unauthorized) # 401
        end
      end

      context 'when bad password' do
        let(:encoded) { Base64.encode64("#{user.email}:#{user.password}-fail") }

        it 'not authorized' do
          post '/api/v1/api-keys', headers: headers
          expect(response).to have_http_status(:unauthorized) # 401
        end
      end

      context 'when good credentials' do
        let(:encoded) { Base64.encode64("#{user.email}:#{user.password}") }

        it 'creates an ApiKey' do
          post '/api/v1/api-keys', headers: headers
          expect(response).to have_http_status(:created)
        end
      end
    end
  end

  describe 'DELETE /api/v1/api-keys' do
    let(:headers) { { 'Authorization' => "Bearer #{api_key.token}" } }

    context 'when valid bearer token provided' do
      let(:admin_user) { create(:user, :with_api_keys) }
      let(:api_key) { admin_user.api_keys.first }

      context 'when attempting to revoke an api key' do
        it 'destroys an ApiKey for a user' do
          expect(admin_user.api_keys.length).to eq 1
          delete "/api/v1/api-keys/#{api_key.id}", headers: headers

          admin_user.reload
          expect(response).to have_http_status(:ok) # 200
          expect(admin_user.api_keys.length).to eq 0

          json = JSON.parse(response.body)
          expect(json['status']).to eq 'success'
          expect(json['message']).to eq "deleted id #{api_key.id}"
        end
      end
    end

    context 'when invalid bearer token provided' do
      let(:admin_user) { create(:user, :with_api_keys) }
      let(:api_key) { admin_user.api_keys.first }
      let(:headers) { { 'Authorization' => "Bearer invalid-token" } }

      context 'when attempting to revoke an api key' do
        it 'does not destroy an ApiKey for a user' do
          expect(admin_user.api_keys.length).to eq 1
          delete "/api/v1/api-keys/#{api_key.id}", headers: headers

          admin_user.reload
          expect(response).to have_http_status(:unauthorized) # 401
          expect(admin_user.api_keys.length).to eq 1
        end
      end
    end
  end
end
