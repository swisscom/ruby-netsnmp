# frozen_string_literal: true

require "bundler/gem_tasks"

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
  task ci: %w[spec rubocop]
end
