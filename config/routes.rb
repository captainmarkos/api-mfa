Rails.application.routes.draw do
  namespace :api do
    namespace :v1 do
      resources :api_keys, path: '/api-keys', only: [:index, :create, :destroy]
      resources :second_factors, path: 'second-factors'
    end
  end
end
