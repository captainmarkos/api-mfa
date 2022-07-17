# db/seeds.rb

emails = ['foo@woohoo.com', 'bar@yahoo.com', 'merp@flerp.com']

emails.each do |email|
  user = User.create!(email: email, password: 'topsecret')
  user.api_keys.create!(token: SecureRandom.hex)
end
