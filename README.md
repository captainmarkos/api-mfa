## API Auth Keys with 2FA

In **[API Auth Keys with Rails](README-part-1.md)** we implement API key authentication without using Devise.  This part for API auth keys with 2FA builds on that.

Here we are going to add 2FA into the app authentication flow.  This should cover how to implement a flexible second factor model which can be extended to support other types of second factors such as backup codes and U2F hardware keys.

- [Before Getting Started](#before-getting-started)
- [Creating a Second Factor Table](#creating-a-second-factor-table)
- [Managing Second Factors](#managing-second-factors)
- [Generate Provisioning URI](#generate-provisioning-uri)
- [Adjusting the Auth Flow](#adjusting-the-auth-flow)


### Before Getting Started

Let's start off with some definitions which most are obvious but no assumptions.

- 2FA : 2nd Factor Authentication
- MFA : Multi Factor Authentication
- U2F : Universal 2nd Factor 
- OTP : One Time Password
- TOTP : Time-based One Time Password
- ROTP : Ruby One Time Password - [https://github.com/mdp/rotp](https://github.com/mdp/rotp)


Let's add api versioning to our app.  The directory structure change is the following

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

```bash
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

Next, let's use that `token` from the above curl to add a second factor for the current user.  The `Api::V1::SecondFactorsController` requires a password if a second factor has not been added yet.  We adjust our request to include the user's `password`.

```bash
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


It just so happens that I already use [Authy](https://authy.com/) so we'll go with that.  There's mobile and desktop versions of the app.

But we can't just send the raw `otp_secret` to the client — QR code scanners don't understand random strings.


### Generate Provisioning URI

We need to generate a `"provisioning URI"`, which is a format QR code scanners can understand. Let's adjust our `SecondFactor` model to do so.

```ruby
class SecondFactor < ApplicationRecord
  ...

  def provisioning_uri
    return if enabled?

    totp = ROTP::TOTP.new(opt_secret, issuer: OTP_ISSUER)
    totp.provisioning_uri(user.email)
  end

  ...
end
```

Checkout [ROTP::TOTP#provisioning_uri](https://github.com/mdp/rotp#generating-qr-codes-for-provisioning-mobile-apps)

Now we can send that `provisioning_uri` to the client, instead of the `otp_secret`.  Then we'll use that value within a QR code rendering component.

Run this in the console to get a `provisioning_uri`.
```ruby
[1] pry(main)> totp = ROTP::TOTP.new(SecureRandom.hex, issuer: "Bob Marley")
=> #<ROTP::TOTP:0x0000000112322d38
 @digest="sha1",
 @digits=6,
 @interval=30,
 @issuer="Bob Marley",
 @secret="5987db791fdbd076b49be4b120d6534b">

[3] pry(main)> totp.provisioning_uri('bob@gmail.com')
=> "otpauth://totp/Bob%20Marley:bob%40gmail.com?secret=5987db791fdbd076b49be4b120d6534b&issuer=Bob%20Marley"
```

Install `qrencode`

```bash
brew install qrencode
```

Using the `provisioning_uri` from the rails console above we can create a QR code.

```bash
qrencode -o QR_CODE_IMAGE.png -d 300 -s 8 "otpauth://totp/Bob%20Marley:bob%40gmail.com?secret=5987db791fdbd076b49be4b120d6534b&issuer=Bob%20Marley"
```

![](QR_CODE_IMAGE.png?raw=true)


### Adjusting the Auth Flow

Next, we're going to want to update our authentication flow to verify a user's second factor. In our case, our only authentication endpoint is the one where you generate a new API key, covered in [Part 1](README-part-1.md).

Let's edit the `ApiKeysController` and verify the user's second factor.

```ruby
class Api::V1::ApiKeysController < Api::ApiBaseController
  ...

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

  ...

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
```

A couple assertions were added to the auth flow:
  1. when the user has a second factor, we assert that an `otp` param be provied.
  2. when the user has a second factor, we assert that the `otp` param is verified.

We have two separate steps for this to make things easier on the front-end.  By sending 2 different error codes, one for when the OTP is required by missing, and one where the OTP was provided but invalid, allows us to adjust our login UI accordingly.




