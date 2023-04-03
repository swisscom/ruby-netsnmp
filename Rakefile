# frozen_string_literal: true

require "bundler/gem_tasks"
require 'rake/extensiontask'

Rake::ExtensionTask.new('netsnmp_ext')

begin
  require "rspec/core/rake_task"

  desc "runs the tests"
  RSpec::Core::RakeTask.new
rescue LoadError
end

begin
  require "rubocop/rake_task"

  desc "Run rubocop"
  task :rubocop do
    RuboCop::RakeTask.new
  end
rescue LoadError
end

namespace :coverage do
  desc "Aggregates coverage reports"
  task :report do
    return unless ENV.key?("CI")

    require "simplecov"
    SimpleCov.collate Dir["coverage/**/.resultset.json"]
  end
end

task default: [:spec]

namespace :spec do
  desc "runs tests, check coverage, pushes to coverage server"
  if RUBY_VERSION >= "3.0.0"
    task ci: %w[spec rubocop]
  else
    task ci: %w[spec]
  end
end
