require File.expand_path('../lib/netsnmp/core/version',__FILE__)

Gem::Specification.new do |gem|
  gem.name        = "netsnmp-core"
  gem.summary     = "Ruby Wrapper to the net-snmp C library, focused on the v3"
  gem.description = <<DESC
This library allows one to use the net-snmp methods within the ruby VM. It doesn't try to do much more than that though. 
DESC
  gem.requirements = []
  gem.version     = NETSNMP::Core::VERSION
  gem.license     = "Apache-2.0"
  gem.authors     = ["Tiago Cardoso"]
  gem.email       = "cardoso_tiago@hotmail.com"
  gem.homepage    = ""
  gem.platform    = Gem::Platform::RUBY
  gem.required_ruby_version = '>=2.0.0'

  # Manifest
  gem.files         = `git ls-files`.split("\n") - Dir['tmp/**/*']
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ["lib"]

  gem.executables = Dir["bin/*"].map { |e| File.basename e }
  gem.add_runtime_dependency "ffi", ["~> 1.9"]
  gem.add_runtime_dependency "RubyInline", ["~> 3.12"]

  gem.add_development_dependency "rake", ["~> 10.4.2"]
  gem.add_development_dependency "rspec", ["~> 3.3.0"]
  gem.add_development_dependency "simplecov", ["~> 0.10.0"]
end
