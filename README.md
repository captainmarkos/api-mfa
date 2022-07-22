## API Auth Key with 2FA

**[Part 1](#part-1)** we implement API key authentication without using Devise.  When it comes to authentication, Ruby on Rails is a batteries-included framework. Devise is over-kill for an API.

- [Create App and Setup](#create-app-and-setup)
- [Create a User Model](#create-a-user-model)
- [Create an API Key Model](#create-an-api-key-model)
- [Create Seed Data](#create-seed-data)
- [Routes for API Key Authentication](#routes-for-api-key-authentication)
- [Create a Concern for API Key Authentication](#create-a-concern-for-api-key-authentication)
- [Controlling API Key Authentication](#controlling-api-key-authentication)
- [Create an API Key](#create-an-api-key)
- [Listing API Keys](#listing-api-keys)
- [Revoking API Keys](#revoking-api-keys)
- [Patching Vulnerabilities](#patching-vulnerabilities)

**[Part 2](#part-2)** we are going to add 2FA into the app authentication flow.  We will cover how to implement a flexible second factor model which can be extended to support other types of second factors such as backup codes and U2F hardwardware keys.

- [Before Getting Started](#before-getting-started)
- [Creating a Second Factor Table](#creating-a-second-factor-table)
- [Managing Second Factors](#managing-second-factors)

### Create App and Setup

```bash
rails new api-mfa --api --database sqlite3 --skip-active-storage --skip-action-cable --skip-test
```


#### Rename main Branch to master

First rename `main` to `master` in the local repo.

```bash
git branch -m main master
```

So far, so good! The local branch has been renamed - but we now need to make some changes on the remote repository.

```bash
git push -u origin master
```

We now have a new branch on the remote named `master`. Let's go on and remove the old `main` branch on the remote.

```bash
git push origin --delete main
```


#### Add Gems

```ruby
gem "bcrypt", "~> 3.1.7"

group :development, :test do
  ...
  gem 'pry-rails'
  gem 'pry-byebug'
  gem 'pry-theme'
  gem 'rubocop', require: false
  gem 'rspec-rails'
  gem 'factory_bot_rails'
  gem 'faker', :git => 'https://github.com/faker-ruby/faker.git', :branch => 'master'
end

group :test do
  gem 'shoulda-matchers', '~> 5.0'
  gem 'simplecov', require: false
  gem 'database_cleaner-active_record', require: false
end
```


#### Turn off irb autocomplete in rails console

```bash
cat >> ~/.irbrc
IRB.conf[:USE_AUTOCOMPLETE] = false
```

The [pry-theme gem](https://github.com/kyrylo/pry-theme) adds some spice to the rails console.

```ruby
[1] pry(main)> pry-theme install vividchalk

[2] pry(main)> pry-theme try vividchalk

[3] pry(main)> pry-theme list
```

```bash
cat >> .pryrc
Pry.config.theme = 'vividchalk'
# Pry.config.theme = 'tomorrow-night'
# Pry.config.theme = 'pry-modern-256'
# Pry.config.theme = 'ocean'
```


## Part 1

### Create a User Model

Firstly, we'll need a user's table.  Pretty standard stuff.

```bash
bin/rails generate migration CreateUsers
```

Population with the following:

```ruby
class CreateUsers < ActiveRecord::Migration[7.0]
  def change
    create_table :users do |t|
      t.string :email, null: false
      t.string :password_digest, null: false

      t.timestamps
    end
  end
end
```

Apply the migration:

```bash
bin/rails db:migrate
```

Lastly, we'll create the actual `User` model:

```ruby
class User < ApplicationRecord
  has_secure_password
end
```

Rails has out-of-the-box support for user password authentication using the `has_secure_password` concern. Here's the doc for [ActiveModel::SecurePassword](https://api.rubyonrails.org/v7.0.3/classes/ActiveModel/SecurePassword/ClassMethods.html) and the [APIdoc](https://apidock.com/rails/v4.0.2/ActiveModel/SecurePassword/ClassMethods/has_secure_password).  You Don't Need Devise.


### Create an API Key Model

We need another model for `ApiKey`.

```bash
bin/rails generate migration CreateApiKeys
```

```ruby
class CreateApiKeys < ActiveRecord::Migration[7.0]
  def change
    create_table :api_keys do |t|
      t.references :bearer, polymorphic: true, index: true
      t.string :token, null: false

      t.timestamps
    end

    add_index :api_keys, :token, unique: true
  end
end
```

Note that we make this polymorphic.  In doing so we can have multiple `"bearers"`.

```bash
bin/rails db:migrate
```

Now we'll create the `ApiKey` model and add the API key association to the `User` model.

```ruby
class ApiKey < ApplicationRecord
  belongs_to :bearer, polymorphic: true
end
```

```ruby
class User < ApplicationRecord
  has_many :api_keys, as: :bearer

  ...
end
```


### Create Seed Data

To verify our work we'll make some seed data and drive from the rails console.

```ruby
# db/seeds.rb

emails = ['foo@woohoo.com', 'bar@yahoo.com', 'merp@flerp.com']

emails.each do |email|
  user = User.create!(email: email, password: 'topsecret')
  user.api_keys.create!(token: SecureRandom.hex)
end
```

Generate the seed data and then hop into the rails console.

```bash
bin/rails db:seed

bin/rails console
```

```ruby
[1] pry(main)> User.first.authenticate('foo')
=> false

[2] pry(main)> User.first.authenticate('topsecret')
=> #<User:0x00000001235356c8
 id: 5,
 email: "foo@woohoo.com",
 password_digest: "$2a$12$SozPmTmi2L2dcPQxbPk2ZuqlEgWyf0R9CLAdhPeMXXtlyfPLjfv42",
 created_at: Sat, 09 Jul 2022 20:11:08.825997000 UTC +00:00,
 updated_at: Sat, 09 Jul 2022 20:11:08.825997000 UTC +00:00>


[3] pry(main)> User.first.api_keys
=> [#<ApiKey:0x00000001248c5e40
  id: 2,
  bearer_type: "User",
  bearer_id: 5,
  token: "8b0de4dc40339cd7745cf2128edb13c9",
  created_at: Sat, 09 Jul 2022 20:11:08.835937000 UTC +00:00,
  updated_at: Sat, 09 Jul 2022 20:11:08.835937000 UTC +00:00>]
```


### Routes for API Key Authentication

Let's setup some routes:

- `GET /api-keys`: to list a bearer's API keys
- `POST /api-keys`: create a new API key - a standard 'login'
- `DELETE /api-keys`: to revoke the current API key - 'logout'

```ruby
Rails.application.routes.draw do
  ...

  # If we use `resources` then we would need to manage the ApiKey ids for
  # the destroy.  For simplicity we'll do the below but putting note here.
  get '/api-keys', to: 'api_keys#index'
  post '/api-keys', to: 'api_keys#create'
  delete '/api-keys', to: 'api_keys#destroy'
  ...
end
```


### Create a Concern for API Key Authentication

Create a typical Rails concern that allows controllers to require API key authentication `app/controllers/concerns/api_key_authenticatable.rb`.

```ruby
module ApiKeyAuthenticatable
  extend ActiveSupport::Concern

  include ActionController::HttpAuthentication::Basic::ControllerMethods
  include ActionController::HttpAuthentication::Token::ControllerMethods
 
  attr_reader :current_api_key
  attr_reader :current_bearer
 
  # Use this to raise an error and automatically respond with
  # a 401 HTTP status code when API key authentication fails
  def authenticate_with_api_key!
    @current_bearer = authenticate_or_request_with_http_token &method(:authenticator)
  end
 
  # Use this for optional API key authentication
  def authenticate_with_api_key
    @current_bearer = authenticate_with_http_token &method(:authenticator)
  end
 
  private
 
  attr_writer :current_api_key
  attr_writer :current_bearer
 
  def authenticator(http_token, options)
    @current_api_key = ApiKey.find_by(token: http_token)
 
    current_api_key&.bearer
  end
end
```

Rails comes batteries-included.  By including a couple core classes we can take advantage of some useful methods:

- `#authenticate_or_request_with_http_token`: authenticate with an HTTP token, otherwise automatically request authentication - rails will respond with a `401 Unauthorized` HTTP status code.
- `#authenticate_with_http_token`: attempt to authenticate with an HTTP token, but don't raise an error if the token ends up being nil.

In both cases, we're going to be passing in our `#authenticator` method to handle the API key lookup. Rails will handle the rest. We'll be storing the current API key bearer and the current API key into controller-level instance variables, `current_bearer` and `current_api_key`, respectively.

See the docs for [ActionController::HttpAuthentication](https://api.rubyonrails.org/classes/ActionController/HttpAuthentication.html).

These methods will handle parsing of the `Authorization` HTTP header. There are multiple HTTP authorization schemes, but these 2 methods will only care about the `Bearer` scheme. We'll get into others.

An `Authorization` header for an API key will look something like this:

```bash
Authorization: Bearer 5c8e4327fd8b2bf3118f82b13890d89dc
```

This is how users will likely be interacting with the API.


### Controlling API Key Authentication

Let's define an empty controller so that we can start testing the API using `curl`.

```ruby
# app/controllers/api_keys_controller.rb

class ApiKeysController < ApplicationController
  def index
  end

  def create
  end

  def destroy
  end
end
```

Smoke test of endpoints with `curl`:

```bash
curl -v -X POST http://localhost:3000/api-keys
< HTTP/1.1 204 No Content

curl -v -X DELETE http://localhost:3000/api-keys
< HTTP/1.1 204 No Content

curl -v -X GET http://localhost:3000/api-keys
< HTTP/1.1 204 No Content
```

So far so good, no 404 or 5xx errors.  Now let's add our authenticatable concern to our controller.

```ruby
# app/controllers/api_keys_controller.rb

class ApiKeysController < ApplicationController
  include ApiKeyAutenticatable

  # Require token auth for index
  prepend_before_action :authenticate_with_api_key!, only: [:index]

  # Optional token auth for logout
  prepend_before_action :authenticate_with_api_key, only: [:destroy]

  ...
```

Run the smoke test again.

```bash
curl -v -X POST http://localhost:3000/api-keys
< HTTP/1.1 204 No Content

curl -v -X DELETE http://localhost:3000/api-keys
< HTTP/1.1 204 No Content

curl -v -X GET http://localhost:3000/api-keys
< HTTP/1.1 401 Unauthorized
```

Note our `GET` request now responds with a `401` HTTP status as intended.  Remember the `POST` doesn't require authentication and it's optional for the `DELETE` end-point.


### Create an API Key

```ruby
class ApiKeysController < ApplicationController
  include ApiKeyAuthenticatable

  ...

  def create
    authenticate_with_http_basic do |email, password|
      user = User.find_by email: email
      if user&.authenticate(password)
        api_key = user.api_keys.create! token: SecureRandom.hex
        render json: api_key, status: :created and return
      end
    end

    render status: :unauthorized
  end

  ...

end
```

Once again we use another method provided by Rails to handle the grunt-work of HTTP authentication.  The `authenticate_with_http_basic` will parse the `Authorization` header.  Unlike the token method variant caring about the `Bearer` scheme, the basic variant only cares about the `Basic` scheme.  Here's the doc [ActionController::HttpAuthentication::Basic::ControllerMethods](https://api.rubyonrails.org/classes/ActionController/HttpAuthentication/Basic/ControllerMethods.html).

A basic `Authorization` header will look something like:

```bash
Authorization: Basic foo@woohoo.com:topsecret
```

The email and password values will actually be base64 encoded and rails will automatically handle parsing and decoding these values.  You don't need Devise!

Let's create our first API key (using email / password from seed data):

```bash
curl -v -X POST http://localhost:3000/api-keys \
        -u foo@woohoo.com:topsecret
< HTTP/1.1 201 Created
{
  "id":5,
  "bearer_type": "User",
  "bearer_id":5,
  "token": "ac49cdacb9fc08330714f1fdfc9145e3",
  "created_at": "2022-07-10T23:19:56.627Z",
  "updated_at": "2022-07-10T23:19:56.627Z"
}
```

Looking in the rails console we now see two ApiKey records for this user (remember one was created via the seed data).

```ruby
[1] pry(main)> user = User.find_by(email: 'foo@woohoo.com')
=> #<User:0x00000001169c6708
 id: 5,
 email: "foo@woohoo.com",
 password_digest: "[FILTERED]",
 created_at: Sat, 09 Jul 2022 20:11:08.825997000 UTC +00:00,
 updated_at: Sat, 09 Jul 2022 20:11:08.825997000 UTC +00:00>

[2] pry(main)> user.api_keys
=> [#<ApiKey:0x0000000116b18368
  id: 2,
  bearer_type: "User",
  bearer_id: 5,
  token: "[FILTERED]",
  created_at: Sat, 09 Jul 2022 20:11:08.835937000 UTC +00:00,
  updated_at: Sat, 09 Jul 2022 20:11:08.835937000 UTC +00:00>,
 #<ApiKey:0x0000000116b30d78
  id: 5,
  bearer_type: "User",
  bearer_id: 5,
  token: "[FILTERED]",
  created_at: Sun, 10 Jul 2022 23:19:56.627854000 UTC +00:00,
  updated_at: Sun, 10 Jul 2022 23:19:56.627854000 UTC +00:00>]
```

Nice, but before we celebrate, let's make sure a bad password and bad emial are properly rejected with a 401 response.

```bash
curl -v -X POST http://localhost:3333/api-keys  -u bar@woohoo.com:topsecret
< HTTP/1.1 401 Unauthorized

curl -v -X POST http://localhost:3333/api-keys  -u foo@woohoo.com:bad_password
< HTTP/1.1 401 Unauthorized
```


### Listing API Keys

Next we'll work on the `#index` action.  Open up the `ApiKeysController` and let's list the API keys for the `current_bearer`.

```ruby
class ApiKeysController < ApplicationController
  include ApiKeyAuthenticatable

  ...

  def index
    render json: current_bearer.api_keys
  end

  ...
```

Smoke test with `curl` (use a valid token).

```bash
curl -v -X GET http://localhost:3333/api-keys -H 'Authorization: Bearer 8b0de4dc40339cd7745cf2128edb13c9'

< HTTP/1.1 200 OK
[
  {
    "id":2,
    "bearer_type": "User",
    "bearer_id":5,
    "token": "8b0de4dc40339cd7745cf2128edb13c9",
    "created_at": "2022-07-09T20:11:08.835Z",
    "updated_at": "2022-07-09T20:11:08.835Z"
  },
  {
    "id":5,
    "bearer_type": "User",
    "bearer_id":5,
    "token": "ac49cdacb9fc08330714f1fdfc9145e3",
    "created_at": "2022-07-10T23:19:56.627Z",
    "updated_at": "2022-07-10T23:19:56.627Z"
  }
]
```


### Revoking API Keys

To revoke an API key we need to update the `#destory` action of our controller.

```ruby
class ApiKeysController < ApplicationController
  include ApiKeyAuthenticatable

  ...

  def destroy
    current_api_key&.destroy
  end

  ...
```

That's all it takes.  Now let's test it out by revoking a API key with `curl`.  First let's find the key in the rails console.

```ruby
[1] pry(main)> User.last.api_keys.first.token
=> "9dc13ad94a52592aeb742cae3e8b620e"
```

Now revoke it with `curl`.

```bash
curl -v -X DELETE http://localhost:3000/api-keys \
        -H 'Authorization: Bearer 9dc13ad94a52592aeb742cae3e8b620e'
< HTTP/1.1 204 No Content
```

We got a `204 No Content` status but did it actually work?  Remember our `DELETE` endpoint has optional API key authentication, unlike the list endpoint which requires authentication, so even if an invalid API key was provided, ti would still return a `204 No Content` status.  This is probably not ideal but it works to exemplify the 2 different authentication actions.

Looking in the rails console we'll see that API key is deleted (and can also be seen by looking at the rails server output).

```bash
Started DELETE "/api-keys" for 127.0.0.1 at 2022-07-12 07:30:38 -0400
Processing by ApiKeysController#destroy as */*
   (0.1ms)  SELECT sqlite_version(*)
  ↳ app/controllers/concerns/api_key_authenticatable.rb:27:in `authenticator'
  ApiKey Load (0.7ms)  SELECT "api_keys".* FROM "api_keys" WHERE "api_keys"."token" = ? LIMIT ?  [["token", "[FILTERED]"], ["LIMIT", 1]]
  ↳ app/controllers/concerns/api_key_authenticatable.rb:27:in `authenticator'
  User Load (0.1ms)  SELECT "users".* FROM "users" WHERE "users"."id" = ? LIMIT ?  [["id", 10], ["LIMIT", 1]]
  ↳ app/controllers/concerns/api_key_authenticatable.rb:29:in `authenticator'
  TRANSACTION (0.0ms)  begin transaction
  ↳ app/controllers/api_keys_controller.rb:27:in `destroy'
  ApiKey Destroy (0.3ms)  DELETE FROM "api_keys" WHERE "api_keys"."id" = ?  [["id", 8]]
  ↳ app/controllers/api_keys_controller.rb:27:in `destroy'
  TRANSACTION (0.4ms)  commit transaction
  ↳ app/controllers/api_keys_controller.rb:27:in `destroy'
Completed 204 No Content in 22ms (ActiveRecord: 2.3ms | Allocations: 9671)
```


### Patching Vulnerabilities

With the current implementation there are 2 vulnerabilities:

1. Storing API keys as plaintext (a big no-no, tokens should be treated like passwords)
2. Tokens could be vulnerable to timing attacks (yes, even with a database index)

Let's start the patch work by renaming the `token` column in the `api_keys` table to be `token_digest`.  For this we can do `bin/rails db:rollback` and the modify the `CreateApiKeys` migration.

```ruby
class CreateApiKeys < ActiveRecord::Migration[7.0]
  def change
    create_table :api_keys do |t|
      t.references :bearer, polymorphic: true, index: true
      t.string :token_digest, null: false

      t.timestamps
    end

    add_index :api_keys, :token_digest, unique: true
  end
end
```

Run the migration with `bin/rails db:migrate`.  Next will update the `ApiKey` model to use a SHA-256 HMAC function, and also provide a method fro authenticating an API key by token.

```ruby
class ApiKey < ApplicationRecord
  HMAC_SECRET_KEY = ENV.fetch('API_KEY_HMAC_SECRET_KEY')

  belongs_to :bearer, polymorphic: true

  before_create :generate_token_hmac_digest

  # Virtual attribute for raw token value allowing us to respond with the
  # API key's non-hashed token value but only directly after creation.
  attr_accessor :token

  def self.authenticate_by_token!(token)
    digest = OpenSSL::HMAC.hexdigest('SHA256', HMAC_SECRET_KEY, token)

    find_by!(token_digest: digest)
  end

  def self.authenticate_by_token(token)
    authenticate_by_token!(token)
  rescue ActiveRecord::RecordNotFound
    nil
  end

  # Add virtual token attribute to serializable attributes
  # and exclude the token's HMAC digest
  def serializable_hash(options = nil)
    h = super(options.merge(except: 'token_digest'))
    h.merge!('token' => token) if token.present?
    h
  end

  private

  def generate_token_hmac_digest
    raise(ActiveRecord::RecordInvalid, 'token is required') if token.blank?

    digest = OpenSSL::HMAC.hexdigest('SHA256', HMAC_SECRET_KEY, token)

    self.token_digest = digest
  end
end
```

A few new methods were added to the `ApiKey` model:

- A new virtual attribute called `token` which holds the plaintext value of our API key's token.  This virtual attribute is only available after the model is created.
- Redefining and API key's `serializable_hash` attributes to include the `token` virtual attribute when present and to always exclude `token_digest`.
- Band and non-bang variants of `authenticate_by_token` which handles securely looking up an API key by token.

We need to set the `API_KEY_HMAC_SECRET_KEY` environment variable.  First generate the secret key in the rails console.

```ruby
[1] pry(main)> SecureRandom.hex(32)
=> "2fd6abfe6d51dce36bc17ffec652c7cc16d9a9b241e04f00f1a38a83db202728"
```

Now set the environment variable.

```bash
export API_KEY_HMAC_SECRET_KEY=2fd6abfe6d51dce36bc17ffec652c7cc16d9a9b241e04f00f1a38a83db202728
```

NOTE that the HMAC secret key should never change.  Changing the secret key will invalidate ALL existing API keys since we would no longer be able to authenticate them.

Lastly we want to update the `#authenticator` method in the `ApiKeyAuthenticatable` concern to use our new `ApiKey.authenticate_by_token` method.

```ruby
module ApiKeyAuthenticatable
  ...

  def authenticator(http_token, options)
    @current_api_key = ApiKey.authenticate_by_token(http_token)

    current_api_key&.bearer
  end
end
```


#### Verifying our Patch

Let's generate a new API key:

```bash
curl -v -X POST http://localhost:3333/api-keys -u merp@flerp.com:topsecret
<  HTTP/1.1 201 Created
{
  "bearer_id" : 20,
  "bearer_type" : "User",
  "created_at" : "2022-07-15T05:25:22.418Z",
  "id" : 8,
  "token" : "76d5068833cb36989af013fbdf71dd34",
  "updated_at" : "2022-07-15T05:25:22.418Z"
}
```

Looks good.  The API key's token is correctly being generated, and the raw token value is still being serialized in the JSON response. But let's assert that the token is no longer being stored in plaintext:

```ruby
[1] pry(main)> ApiKey.last.token_digest
=> "b558cbaaab1b469149027f3bf8840322fad7e564933f356a6e5d9afe217e89e2"
```

Looks correct. Now let's also make sure we can still authenticate with our API key's token, and we also want to assert that we're not leaking our token_digest in the list of serialized API keys.

```bash
curl -v -X GET http://localhost:3000/api-keys -H 'Authorization: Bearer c2d0e6b8bbeb295a8e6f144fe7ba0596'

< HTTP/1.1 200 OK
[
   {
      "id" : 3,
      "bearer_id" : 20,
      "bearer_type" : "User",
      "created_at" : "2022-07-12T16:32:15.148Z",
      "updated_at" : "2022-07-12T16:32:15.148Z"
   },
   {
      "id" : 9,
      "bearer_id" : 20,
      "bearer_type" : "User",
      "created_at" : "2022-07-15T05:36:59.561Z",
      "updated_at" : "2022-07-15T05:36:59.561Z"
   }
]
```

And once again, things look good. But now we have a new issue. Since we can no longer read the tokens of other API keys, we're unable to delete them using our existing API key deletion endpoint. To fix this issue, let's rework our `"logout"` endpoint.

Let's make a change to our `routes.rb` by removing the `get`, `post` and `delete` routes and using the rails `resources` found in [ActionDispatch::Routing::Mapper::Resources](https://api.rubyonrails.org/v7.0.3/classes/ActionDispatch/Routing/Mapper/Resources.html#method-i-resources).

```ruby
Rails.application.routes.draw do
  resources :api_keys, path: '/api-keys', only: [:index, :create, :destroy]
end
```

This will create the following routes and notice the change is that now the `DELETE` needs an `:id`:

```bash
bin/rails routes

  Prefix Verb   URI Pattern             Controller#Action
api_keys GET    /api-keys(.:format)     api_keys#index
         POST   /api-keys(.:format)     api_keys#create
 api_key DELETE /api-keys/:id(.:format) api_keys#destroy
```

So we'll also want to update our controller to revoke API keys by ID, rather than simply revoking the current_api_key.

```ruby
class ApiKeysController < ApplicationController
  include ApiKeyAuthenticatable

  # Require API key authentication
  prepend_before_action :authenticate_with_api_key!, only: [:index, :destroy]

  ...

  def destroy
    api_key = current_bearer.api_keys.find(params[:id]

    api_key.destroy
  end
end
```

Kabam!  The patch added a little bit to the API key model but it resolves vulnerabilities.  And like any good rails dev, specs help to give us more confidence that this works as intended.  That said we can find a request and model spec in the repo.


### To Bear or not to Bear

Since our API keys are polymorphic, we can have multiple authenticatable models such as an `Admin` model or a `PacMan`.  The sky's the limit as long as the code is flexible enough and not expecting a `User` everywhere a bearer is.  There shouldn't be any issues making some obscure model an API key bearer.  Pair this with an authorization gem like `Pundit` and it'll work nicely.


### Wrap Up

We've implemented a login endpoint where we can generate new API keys, a logout endpoint where we can revoke existing API keys, as well as an endpoint allowing us to list the current user's API keys. From here, adding API key authentication to other controller actions is as simple as adding one of the 2 before_action callbacks.

Some people may raise concern that we're "rolling our own auth" here, but that's actually not true. We're using tools that Rails provides for us out-of-the-box. API key authentication doesn't have to be complex, and you most certainly don't have to use a third-party gem like Devise to implement it.


### Resources & Credits

This is my implementation based (closely) off of [this tutorial](https://keygen.sh/blog/how-to-implement-api-key-authentication-in-rails-without-devise/).  All the credit goes to here as this was for my fun and deeper diving into the topic.  Many thanks for this tutorial!


## Part 2

### Before Getting Started

Let's start off with some definitions which most are obvious but no assumptions.

- 2FA : 2 Factor Authentication
- MFA : Multi Factor Authentication
- OTP : One Time Password
- TOTP : Time-based One Time Password
- ROTP : Ruby One Time Password - [https://github.com/mdp/rotp](https://github.com/mdp/rotp)


Next let's add api versioning to our app.  The directory structure change is the following

```bash
# create directories
mkdir app/controllers/api
mkdir app/controllers/api/v1

# move the code
mv app/controllers/api_keys_controller.rb app/controllers/api/v1/

```

Create a new file `app/controllers/api/api_base_controller.rb` and make it look like

```ruby
class Api::ApiBaseController < ApplicationController
end
```

Edit `app/controllers/api/v1/api_keys_controller.rb` to have

```ruby
class Api::V1::ApiKeysController < Api::ApiBaseController
  include ApiKeyAuthenticatable

  ...

end
```


Make the `config/routes.rb` like

```ruby
Rails.application.routes.draw do

  ...

  namespace :api do
    namespace :v1 do
      resources :api_keys, path: '/api-keys', only: [:index, :create, :destroy]
    end
  end
end
```

Smoke test it.  Start the rails server and let's hit with `curl` (remember the seed data in `db/seeds.rb`).

```bash
# create an api key for this user
#
curl -v -X POST http://localhost:3333/api/v1/api-keys -u foo@woohoo.com:topsecret
< HTTP/1.1 201 Created
{
  "id": 4,
  "bearer_type": "User",
  "bearer_id": 1,
  "created_at": "2022-07-17T17:47:49.954Z",
  "updated_at": "2022-07-17T17:47:49.954Z",
  "token": "495e74d76ec5f7d7b7385796eea26fde"
}

# use the token to GET all api_keys records
#
curl -v -X GET http://localhost:3333/api/v1/api-keys -H 'Authorization: Bearer 495e74d76ec5f7d7b7385796eea26fde'
< HTTP/1.1 200 OK
[
   {
      "bearer_id" : 1,
      "bearer_type" : "User",
      "created_at" : "2022-07-17T17:47:14.496Z",
      "id" : 1,
      "updated_at" : "2022-07-17T17:47:14.496Z"
   },
   {
      "bearer_id" : 1,
      "bearer_type" : "User",
      "created_at" : "2022-07-17T17:47:49.954Z",
      "id" : 4,
      "updated_at" : "2022-07-17T17:47:49.954Z"
   }
]

# use the token to DELETE an api_keys record by id
#
curl -v -X DELETE http://localhost:3333/api/v1/api-keys/4 -H 'Authorization: Bearer 495e74d76ec5f7d7b7385796eea26fde'
< HTTP/1.1 200 OK

{
  "status": "success",
  "message": "deleted id 4"
}
```


### Creating a Second Factor Model

```bash
bin/rails generate migration CreateSecondFactors
      invoke  active_record
      create    db/migrate/20220717200348_create_second_factors.rb
```

The migration

```ruby
class CreateSecondFactors < ActiveRecord::Migration[7.0]
  def change
    create_table :second_factors do |t|
      t.references :user, null: false
      t.text :otp_secret, null: false, index: { unique: true }
      t.boolean :enabled, null: false, default: false
      t.timestamps
    end
  end
end
```

Now apply the migration with `bin/rails db:migrate`.

We now need to add the [rotp](https://github.com/mdp/rotp/) gem to the `Gemfile` and install.

Create the model `app/models/second_factor.rb`

```ruby
class SecondFactor < ApplicationRecord
  OTP_ISSUER = 'keygen.example'

  belongs_to :user

  before_create :generate_otp_secret

  validates :user, presence: true

  scope :enabled, -> { where(enabled: true) }

  def verify_with_otp(otp)
    totp = ROTP::TOTP.new(otp_secret, issuer: OTP_ISSUER)

    totp.verify(otp.to_s)
  end

  private

  def generate_otp_secret
    self.otp_secret = ROTP::Base32.random
  end
end
```

Update the `User` model.

```ruby
class User < ApplicationRecord
  ...
  has_many :second_factors
  ...
end
```


### Managing Second Factors

Add new routes for second factors to `config/routes.rb`.

```ruby
Rails.application.routes.draw do
  namespace :api do
    namespace :v1 do
      resources :api_keys, path: '/api-keys', only: [:index, :create, :destroy]
      resources :second_factors, path: 'second-factors'
    end
  end
end
```

Create our `SecondFactorsController` in `app/controllers/api/v1.second_factors_controller.rb`.

```ruby
class Api::V1::SecondFactorsController < Api::ApiBaseController
  include ApiKeyAuthenticatable

  OTP_INVALID_MSG = 'second factor must be valid'
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
          message: OTP_INVALID_MSG,
          code: 'OTP_INVALID'
      ) unless result
    else
      result = current_bearer.authenticate(params[:password])
      raise(
        UnauthorizedRequestError,
        message: PWD_INVALID_MSG,
        code: 'PWD_INVALID'
      ) unless result
    end

    second_factor.save!

    render json: SecondFactorResource.new(second_factor), status: :created
  end

  def update; end

  def destroy; end
end
```

Let's start with the create part in CRUD. Our create method is going to initialize a new second factor for the user, and then either verify the user's current second factor, or verify their password, before saving the second factor to the database.

Before we test it out, we're going to need to add a couple methods to our `User` model.

```ruby
class User < ApplicationRecord

  ...

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
```

The first method will be used to check if the user has a second factor enabled, and the second method will let us authenticate a user's enabled second factor. To test it out, we'll go ahead and generate an API key so we can make a few subsequent requests.

```json
curl -X POST http://localhost:3333/api/v1/api-keys -u foo@woohoo.com:topsecret | json_pp

{
   "bearer_id" : 1,
   "bearer_type" : "User",
   "created_at" : "2022-07-22T14:17:00.884Z",
   "id" : 4,
   "token" : "079ce807b0736d5aefa345754c889c71",
   "updated_at" : "2022-07-22T14:17:00.884Z"
}
```

The [`json_pp` gem](https://rubygems.org/gems/json_pp/versions/0.0.1) I use for formatting json.

Next, let's use that `token` to add a second factor for the current_user.  The `Api::V1::SecondFactorsController`  requires a password if a second factor has not been added yet.  We adjust our request to inclue the user's `password`.

```json
curl -X POST http://localhost:3333/api/v1/second-factors \
     -H 'Authorization: Bearer 079ce807b0736d5aefa345754c889c71' \
     -d password=topsecret | json_pp

{
   "created_at" : "2022-07-22T14:36:04.493Z",
   "enabled" : false,
   "id" : 3,
   "otp_secret" : "JKTBAJX7UMWMMO5KEQ75ENGMIVSUJMHG",
   "updated_at" : "2022-07-22T14:36:04.493Z",
   "user_id" : 1
}
```

Kabam!  Notice the `otp_secret`.  Now we need to get that value into our TOTP authenticator app.  Most authenticator apps will let you input the secret by hand but that's error prone and a terrible user-experience.  Instead what we can do is utilize a QR code drawing lib to render the `otp_secret` client-side, which can be scanned and stored in the TOTP auth app.






### Ruby Fun

```ruby
# some_string = "This is my stance, but it's not a good one."
# transformed = "sihT si ym ecnats, tub s'ti ton a doog eno."
#
# got = some_string.split.map { |i| i.gsub(/[a-zA-Z']+/, &:reverse) }.join(' ')
#
# got == transformed
```