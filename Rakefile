require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'coveralls/rake/task'

desc "runs the tests and sends to coveralls server"
Coveralls::RakeTask.new

desc "runs the tests"
RSpec::Core::RakeTask.new

task default: [:spec]



namespace :spec do
  desc "runs the tests in coverage mode"
  task :coverage do
    ENV['COVERAGE'] = "true"
    Rake::Task["spec"].execute
  end

  desc "runs tests, check coverage, pushes to coverage server"
  task :ci => ['spec:coverage', 'coveralls:push']
end


