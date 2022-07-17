require 'simplecov'

SimpleCov.start 'rails' do
  # exclude files in these folders
  add_filter %r{^/spec/}
  add_filter %r{^/config/}
end
