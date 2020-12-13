# frozen_string_literal: true

source "https://rubygems.org/"
ruby RUBY_VERSION

gemspec

gem "rake", "~> 12.3"

gem "coveralls", require: false
gem "rspec", "~> 3.5"

group :development do
  gem "pry"
end

gem "celluloid-io", "~> 0.17"
gem "nio4r", "~> 1.2" if RUBY_VERSION < "2.2"

platforms :mri do
  gem "pry-byebug", require: false
  gem "stackprof", require: false
  gem "xorcist", require: false
end

gem "rubocop", "0.52.1", require: false
