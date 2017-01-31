source "https://rubygems.org/"
ruby RUBY_VERSION

gemspec

gem 'coveralls', require: false

group :development do
  gem 'pry'
end

if RUBY_VERSION < "2.2"
  gem "nio4r", "~> 1.2"
end

platforms :mri do
  gem "pry-byebug", require: false
  gem "stackprof", require: false
end

gem "xorcist"
