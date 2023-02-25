# frozen_string_literal: true

source "https://rubygems.org/"
ruby RUBY_VERSION

gemspec

gem "rake", "~> 12.3"
gem "rspec", "~> 3.5"

gem "pry"

platform :mri, :truffleruby do
  gem "pry-byebug", require: false
  gem "xorcist", require: false
end

if RUBY_VERSION >= "3.0.0"
  gem "rubocop"
  gem "rubocop-performance"
end

gem "rbs" if RUBY_VERSION >= "3.0"

if RUBY_VERSION < "2.2.0"
  gem "simplecov", "< 0.11.0", require: false
else
  gem "celluloid-io", "~> 0.17" if RUBY_VERSION >= "2.3.0"

  if RUBY_VERSION < "2.4"
    gem "simplecov", "< 0.11.0", require: false
  elsif RUBY_VERSION < "2.5.0"
    gem "simplecov", "< 0.21.0", require: false
  else
    gem "simplecov", require: false
  end

end
