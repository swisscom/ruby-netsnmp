require File.expand_path('../lib/netsnmp/version',__FILE__)

Gem::Specification.new do |gem|
  gem.name        = "netsnmp"
  gem.summary     = "SNMP Client library"
  gem.description = <<DESC
Wraps the net-snmp core usage into idiomatic ruby.
It is designed to support as many environments and concurrency frameworks as possible.
DESC
  gem.requirements = ['net-snmp']
  gem.version     = NETSNMP::VERSION
  gem.license     = "Apache-2.0"
  gem.authors     = ["Tiago Cardoso"]
  gem.email       = "cardoso_tiago@hotmail.com"
  gem.homepage    = ""
  gem.platform    = Gem::Platform::RUBY
  gem.required_ruby_version = '>=2.0.0'
  gem.metadata["allowed_push_hosts"] = "https://rubygems.org/"

  # Manifest
  gem.files         = `git ls-files`.split("\n") - Dir['tmp/**/*']
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ["lib"]

  gem.executables = Dir["bin/*"].map { |e| File.basename e }
  gem.add_runtime_dependency "ffi", ["~> 1.9"]
  unless RUBY_PLATFORM == "java"
    gem.add_runtime_dependency "RubyInline", ["~> 3.12"]
  end

  gem.add_development_dependency "rake", ["~> 10.4.2"]
  gem.add_development_dependency "rspec", ["~> 3.3.0"]

  gem.add_development_dependency "celluloid-io", ["~> 0.17.2"]
end
