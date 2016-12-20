# netsnmp 

[![Build Status](https://travis-ci.org/swisscom/ruby-netsnmp.svg?branch=master)](https://travis-ci.org/swisscom/ruby-netsnmp)
[![Coverage Status](https://coveralls.io/repos/github/swisscom/ruby-netsnmp/badge.svg?branch=master)](https://coveralls.io/github/swisscom/ruby-netsnmp?branch=master)
[![Code Climate](https://codeclimate.com/github/swisscom/ruby-netsnmp/badges/gpa.svg)](https://codeclimate.com/github/swisscom/ruby-netsnmp)
[![Docs](http://img.shields.io/badge/yard-docs-blue.svg)](https://www.rubydoc.info/github/swisscom/ruby-netsnmp/master)

The `netsnmp` gem provides a ruby native implementation of the SNMP protocol (v1/2c abd v3).

This gem started as a cleanup from [net-snmp](https://github.com/mixtli/net-snmp) and its follow-up [net-snmp2](https://github.com/jbreeden/net-snmp2), both of which have been mostly inactive for the last year(s).

## Installation

Add this line to your application's Gemfile:

```ruby 
gem 'netsnmp'
```

And then execute:

```
$ bundle
```

Or install it yourself as:

```
$ gem install netsnmp
```

## Why?

You may ask, why not just use the aforementioned? I'll try to sum up the reasons. The following list is almost related to them using FFI/native extensions and the netsnmp C library: 

* Lack of support for some specific netsnmp C versions. 
* Memory Leaks (both leave the responsibility of cleaning pdus to the user, and this usually creates memory leak when the responses fail). 
* Unreliable on a ruby implementation other than 2.0.0-p576, that I know of at least.
* Network I/O not controlled by the Ruby VM, thereby blocking the GVL, and making it impossible to be used with evented IO (eventmachine, nio4r).  
* The default sync request calls block the whole VM, making multi-threading a non-factor, forcing you to resort to multiprocess for concurrency. 

All of these issues are resolved here. 

## Philosophy

The main motto of the gem is: API economy. As less moving parts as possible. New features can be discussed and integrated, but they all must abide to this philosophy. 

The main purpose of this gem is: SNMP v3 support. Why? Security by default. Because it's the only one with authentication and security features integrated.

## Features

* Client Interface, which supports SNMP v3, v2c, and v1
* Supports get, getnext, set and walk calls. 
* Proxy support (for eventmachine/celluloid-io)
* Ruby >= 2.1 support
* Pure Ruby (no FFI)

## Examples

You can use the docker container provided under spec/support to test against these examples (the port used in the examples should be the docker external port mapped to port 161). 

```ruby
require 'netsnmp'

# example you can test against the docker simulator provided. port attribute might be different. 
manager = NETSNMP::Client.new(host: "localhost", port: 33445, username: "simulator",
                              auth_password: "auctoritas", auth_protocol: :md5, 
                              priv_password: "privatus", priv_protocol: :des,
                              context: "a172334d7d97871b72241397f713fa12")

# SNMP get
manager.get("sysName.0") #=> 'tt'

# SNMP walk
manager.walk("sysORDescr") do |oid_code, value|
  # do something with them  
  puts "for #{oid_code}: #{value}"
end

manager.close

# SNMP set
manager2 = NETSNMP::Client.new(host: "localhost", port: 33445, username: "simulator",
                               auth_password: "auctoritas", auth_protocol: :md5, 
                               priv_password: "privatus", priv_protocol: :des,
                               context: "0886e1397d572377c17c15036a1e6c66")

# setting to 43, becos yes
manager2.set("sysUpTimeInstance", 43) 

manager2.close
```

SNMP v2/v1 examples will be similar (beware of the differences in the initialization attributes). 

## Tests

This library uses RSpec. The client specs are "integration" tests, in that we communicate with an snmp agent simulator. 

To start the simulator locally, you'll need docker 1.9 or higher (Why 1.9? ```--build-arg``` parameter support was needed for our builds in the CI. You could use a lower version by providing the proxy environment variables in the Dockerfile directly, provided you don't merge these changes to master, thereby exposing your proxy). 

```
> spec/support/start_docker.sh
```

this builds and starts the docker image in deamonized mode. You can afterwards run your specs:

```
> bundle exec rspec
```

To stop the image, you can just:

```
> spec/supoprt/stop_docker.sh
```

## Contributing

* Fork this repository
* Make your changes and send me a pull request
* If I like them I'll merge them
* If I've accepted a patch, feel free to ask for a commit bit!

## TODO

There are some features which this gem doesn't support. It was built to provide a client (or manager, in SNMP language) implementation only, and the requirements were fulfilled. However, these notable misses will stand-out:

* No MIB support (you can only work with OIDs)
* No server (Agent, in SNMP-ish) implementation.
* No getbulk support. 

So if you like the gem, but would rather have these features implemented, please help by sending us a PR and we'll gladly review it.

