Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Defines the root path route ("/")
  # root "articles#index"

  resources :api_keys, path: '/api-keys', only: [:index, :create, :destroy]

  #get '/api-keys', to: 'api_keys#index'
  #post '/api-keys', to: 'api_keys#create'
  #delete '/api-keys', to: 'api_keys#destroy'
end
