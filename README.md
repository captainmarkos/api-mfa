## API Auth Keys with 2FA

In **[API Auth Keys with Rails](README-part-1.md)** we implement API key authentication without using Devise.  This part for API auth keys with 2FA builds on that.

Here we are going to add 2FA into the app authentication flow.  This should cover how to implement a flexible second factor model which can be extended to support other types of second factors such as backup codes and U2F hardware keys.

- [Before Getting Started](#before-getting-started)
- [Creating a Second Factor Table](#creating-a-second-factor-table)
- [Managing Second Factors](#managing-second-factors)
- [Generate Provisioning URI](#generate-provisioning-uri)
- [Adjusting the Auth Flow](#adjusting-the-auth-flow)
- [Fixing a Vulnerability](#fixing-a-vulnerability)
- [Refactoring Notes](#refactoring-notes)
- [Credit](#credit)


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
  include ApiKeyAuthenticatable

  rescue_from ActiveRecord::RecordInvalid, with: -> { render status: :unprocessable_entity }
  rescue_from ActiveRecord::RecordNotUnique, with: -> { render status: :conflict }
  rescue_from ActiveRecord::RecordNotFound, with: -> { render status: :not_found }

  rescue_from UnauthorizedRequestError do |e|
    error = { message: e.message, code: e.code }

    render json: { error: error }, status: :unauthorized
  end
end
```

Create and add to `app/lib/unauthorized_request_error.rb`.

```ruby
class UnauthorizedRequestError < StandardError
  attr_reader :code

  def initialize(message:, code: nil)
    @code = code

    super(message)
  end
end
```

Edit `app/controllers/api/v1/api_keys_controller.rb` to inherit from the new `ApiBaseController`.

```ruby
class Api::V1::ApiKeysController < Api::ApiBaseController

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
        UnauthorizedRequestError.new(
          message: OTP_INVALID_MSG,
          code: 'OTP_INVALID'
        )
      ) unless result
    else
      result = current_bearer.authenticate(params[:password])
      raise(
        UnauthorizedRequestError.new(
          message: PWD_INVALID_MSG,
          code: 'PWD_INVALID'
        )
      ) unless result
    end

    second_factor.save!

    render json: second_factor, status: :created
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

    totp = ROTP::TOTP.new(otp_secret, issuer: OTP_ISSUER)
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
      UnauthorizedRequestError.new(
        message: 'second factor is required',
        code 'OTP_REQUIRED'
      )
    )
  end

  def second_factor_invalid
    raise(
      UnauthorizedRequestError.new(
        message: 'second factor is invalid',
        code: 'OTP_INVALID'
      )
    )
  end
end
```

A couple assertions were added to the auth flow:
  1. when the user has a second factor, we assert that an `otp` param be provied.
  2. when the user has a second factor, we assert that the `otp` param is verified.

We have two separate steps for this to make things easier on the front-end.  By sending 2 different error codes, one for when the OTP is required by missing, and one where the OTP was provided but invalid, allows us to adjust our login UI accordingly.


Let's check it out:

```bash
curl -X POST http://localhost:3333/api/v1/api-keys -u foo@woohoo.com:topsecret | json_pp

{
   "bearer_id" : 1,
   "bearer_type" : "User",
   "created_at" : "2022-08-13T12:23:37.194Z",
   "id" : 7,
   "token" : "78029054cf1b11c7dbe184b8184a6f67",
   "updated_at" : "2022-08-13T12:23:37.194Z"
}
```

Wait a minute, shouldn't we have been prompted for a second factor?  Well, no, we don't have our second factor enabled yet.

Let's open up the `SecondFactorsController` and work on the `#update` method.

```ruby
class Api::V1::SecondFactorsController < Api::ApiBaseController
  MFA_INVALID_MSG = 'second factor must be valid'
  PWD_INVALID_MSG = 'password must be valid'

  ...

  def update
    second_factor = current_bearer.second_factors.find(params[:id])

    # Verify this particular 2nd factor (which may not be enabled yet).
    raise(
      UnauthorizedRequestError.new(
        message: MFA_INVALID_MSG,
        code: 'OTP_INVALID'
      )
    ) unless second_factor.verify_with_otp(params[:otp])

    second_factor.update!(enabled: params[:enabled])

    render json: second_factor, status: :ok
  end

  ...
end
```


Here, we're verifying the current second factor using an OTP, to assert that the end-user has correctly set up their authenticator app. To test, we'll want to send a PATCH request to update our second factor's enabled attribute.

```bash
# Create an auth token if necessary:
curl -v -X POST http://localhost:3333/api/v1/api-keys -u foo@woohoo.com:topsecret

{
   "bearer_id" : 1,
   "bearer_type" : "User",
   "created_at" : "2022-08-19T15:14:19.724Z",
   "id" : 9,
   "token" : "4cacf5338d50a9c640dbed74f2525ea4",
   "updated_at" : "2022-08-19T15:14:19.724Z"
}

# Enable MFA
curl -X PATCH http://localhost:3333/api/v1/second-factors/1 \
     -H 'Authorization: Bearer 4cacf5338d50a9c640dbed74f2525ea4' \
     -d enabled=1

{
   "error" : {
      "code" : "OTP_INVALID",
      "message" : "second factor must be valid"
   }
}
```

Well, that didn't work. It didn't work because our `#update` requires us to send an OTP, in order to verify that we correctly set up our second factor within an authenticator app.  Because remember, once this second factor is enabled, the user will not be able to authenticate without an OTP moving forward.  So if things are not set up correctly, then the user gets locked out of their account.

To test, you can go ahead and take this time to render the provisioning URI into a QR code and scan it with your authenticator app if that works for you, but for the sake of time, let's use the Rails console instead.

```ruby
> s = SecondFactor.first
> totp = ROTP::TOTP.new(s.otp_secret)
> totp.now
=> "666127"
```

Now, anytime we want a new OTP, we can call totp.now in our Rails console. But we have to be quick! The OTPs only last for about 30 seconds.

So let's try again, but with an OTP this time.

```bash
curl -X PATCH http://localhost:3333/api/v1/second-factors/1 \
     -H 'Authorization: Bearer 4cacf5338d50a9c640dbed74f2525ea4' \
     -d enabled=1 \
     -d otp=666127

{
   "created_at" : "2022-07-22T14:22:26.052Z",
   "enabled" : true,
   "id" : 1,
   "otp_secret" : "G2OTDGZHNXJR44OF5HV4QUW4L3KV2X5A",
   "updated_at" : "2022-08-19T17:39:17.907Z",
   "user_id" : 1
}
```

We can see the enabled attribute is now `true`, so let's go ahead and try authenticating one more time.

```bash
curl -v -X POST http://localhost:3333/api/v1/api-keys -u foo@woohoo.com:topsecret

< HTTP/1.1 401 Unauthorized
{
   "error" : {
      "code" : "OTP_REQUIRED",
      "message" : "one time password is required"
   }
}
```

Great, we got the expected OTP_REQUIRED code! But now what happens when we provide an invalid OTP?

```bash
curl -X POST http://localhost:3333/api/v1/api-keys \
     -u foo@woohoo.com:topsecret \
     -d otp=000000

{
   "error" : {
      "code" : "OTP_INVALID",
      "message" : "one time password is invalid"
   }
}
```

KABAM!  Just what we expected, our `OTP_INVALID` code.  And lastly, what happens when we provide a valid OTP?  If the rails console is still up we can run `totp.now` and get the new otp.

```bash
curl -X POST http://localhost:3333/api/v1/api-keys \
     -u foo@woohoo.com:topsecret \
     -d otp=970865

{
   "bearer_id" : 1,
   "bearer_type" : "User",
   "created_at" : "2022-08-19T17:48:42.548Z",
   "id" : 10,
   "token" : "11e573aaac339b46fd918222883c9131",
   "updated_at" : "2022-08-19T17:48:42.548Z"
}
```

Success!  We've successfully implemented TOTP 2FA verification into our app's normal authentication flow. This is great because not only is TOTP 2FA free, but it's more secure than SMS 2FA.


### Fixing a Vulnerability

Before we close, we need to resolve a vulnerability in our OTP implementation. Right now, OTP tokens can be reused. We need to ensure that OTPs (one-time-passwords) are actually, as the name would suggest, one-time passwords.


To do so, we'll need to add a new column to our `second_factors` table, create the migration and apply.

```bash
bin/rails generate migration AddOtpVerifiedAtToSecondFactors
```

```ruby
class AddOtpVerifiedAtToSecondFactors < ActiveRecord::Migration[7.0]
  def change
    add_column :second_factors, :otp_verified_at, :datetime, null: true
  end
end
```

Lastly, we'll want to adjust our OTP verification method to utilize the otp_verified_at column, and also automatically update it when a successful verification occurs.  Edit the `SecondFactor` model method `#verify_with_otp`.

```ruby
class SecondFactor < ApplicationRecord
  ...

  def verify_with_otp(otp)
    # Time-based One Time Password
    totp = ROTP::TOTP.new(otp_secret, issuer: OTP_ISSUER)

    ts = totp.verify(otp.to_s, after: otp_verified_at.to_i)
    update(otp_verified_at: Time.at(ts)) if ts.present?

    ts
  end

  ...
end
```

### TODO

- A `User` can have many `second_factors` so the name is a little awkward to me.  Rename the `SecondFactor` model to `MultiFactorAuth`, associated table `second_factors` -> `multi_factor_auths`, controller and other refrences to the `second_factor` term.  Now it would be said that "a `User` `has_many :multi_factor_auths`".

- Add appropriate tests.


### Refactoring Notes

Looking at the code as compared to this README there will be some discrepencies.  I've refactored some things along the way.  One thing, I don't like is the model name "`SecondFactor`" and other references to the term "second factor".  I think the proper name should be "multi factor" or "multi factor auth" or something but remove the "second" part of the name.  I may change it after writing this README... I may not.


### Credit

I did not create this tuturial.  I followed and did my own personal deep dive into this tutuorial [here](https://keygen.sh/blog/how-to-implement-totp-2fa-in-rails-using-rotp/) so all credit goes there.
