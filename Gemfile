# frozen_string_literal: true

source "https://rubygems.org/"
ruby RUBY_VERSION

gemspec

gem "rake", "~> 12.3"
gem "rspec", "~> 3.5"

platform :mri, :truffleruby do
  gem "xorcist", require: false
end

if RUBY_VERSION >= "3.0.0"
  gem "rubocop"
  gem "rubocop-performance"
end

gem "rbs" if RUBY_VERSION >= "3.0"

if RUBY_VERSION < "2.3"
  gem "simplecov", "< 0.11.0"
elsif RUBY_VERSION < "2.4"
  gem "docile", "< 1.4.0"
  gem "simplecov", "< 0.19.0"
elsif RUBY_VERSION < "2.5"
  gem "docile", "< 1.4.0"
  gem "simplecov", "< 0.21.0"
else
  gem "simplecov"
end

gem "celluloid-io", "~> 0.17" if RUBY_VERSION >= "2.3.0"
