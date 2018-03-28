# frozen_string_literal: true

source "https://rubygems.org/"
ruby RUBY_VERSION

gemspec

gem "coveralls", require: false

group :development do
  gem "pry"
end

gem "nio4r", "~> 1.2" if RUBY_VERSION < "2.2"

platforms :mri do
  gem "pry-byebug", require: false
  gem "stackprof", require: false
end

gem "xorcist"

gem "rubocop", "0.52.1", require: false
