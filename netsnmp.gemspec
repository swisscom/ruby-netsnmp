# frozen_string_literal: true

require File.expand_path("../lib/netsnmp/version", __FILE__)

Gem::Specification.new do |gem|
  gem.name        = "netsnmp"
  gem.summary     = "SNMP Client library"
  gem.description = <<-DESC
    Wraps the net-snmp core usage into idiomatic ruby.
    It is designed to support as many environments and concurrency frameworks as possible.
  DESC
  gem.requirements = ["net-snmp"]
  gem.version     = NETSNMP::VERSION
  gem.license     = "Apache-2.0"
  gem.authors     = ["Tiago Cardoso"]
  gem.email       = "cardoso_tiago@hotmail.com"
  gem.homepage    = ""
  gem.platform    = Gem::Platform::RUBY
  gem.metadata["allowed_push_host"] = "https://rubygems.org/"

  # Manifest
  gem.files = Dir["LICENSE.txt", "README.md", "AUTHORS", "lib/**/*.rb", "sig/**/*.rbs"]
  gem.test_files    = Dir["spec/**/*.rb"]
  gem.require_paths = ["lib"]

  gem.add_runtime_dependency "parslet"
end
