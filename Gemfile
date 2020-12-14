# frozen_string_literal: true

source "https://rubygems.org/"
ruby RUBY_VERSION

gemspec

gem "rake", "~> 12.3"
gem "rspec", "~> 3.5"

group :development do
  gem "pry"
end

gem "celluloid-io", "~> 0.17"

platforms :mri do
  gem "pry-byebug", require: false
  gem "stackprof", require: false
  gem "xorcist", require: false
end

gem "rubocop", "0.52.1", require: false

gem "rbs", git: "https://github.com/ruby/rbs.git", branch: "master" if RUBY_VERSION >= "3.0"

if RUBY_VERSION < "2.2"
  gem "celluloid-io", "~> 0.17.3"
  gem "nio4r", "~> 1.2"
  gem "simplecov", "< 0.11.0", require: false
elsif RUBY_VERSION < "2.3"
  gem "simplecov", "< 0.11.0", require: false
else
  gem "simplecov", require: false
end
