# netsnmp 

The netsnmp gem provides a ruby DSL to handle SNMP queries. It currently uses the net-snmp C library using the FFI interface. 

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

You may ask, why not just use the aforementioned? I'll try to sum up the reasons. 

* Lack of support for some specific net-snmp versions. 
* Memory Leaks (both leave the responsibility of cleaning pdus to the user, and this usually creates memory leak when the responses fail). 
* Lack of support for some ruby > 2.1 GC directives, which makes the VM crash under certain circumstances. 
* Iffy EventMachine support (they basically send the request pdu, and schedule the reads to the reactor, and not really reacting on the socket handle).
* Lack of support for NIO4r/Celluloid-IO (the other event loop, besides EM, that counts in the ruby world). 
* The default sync request calls block the whole VM, making multi-threading a non-factor, forcing you to resort to multiprocess for concurrency. 


## Philosophy

The main motto of the gem is: API economy. As less moving parts as possible. New features can be discussed and integrated, but they all must abide to this philosophy. 

The main purpose of this gem is: SNMP v3 support. Why? Because it's the only one with authentication and security features integrated. SNMP has been a protocol which historically ignored security for many years, and even when it embraced it, its choices are by today's standards considered half-baked (MD5, SHA-1, shrug). Still, some-security is better than no-security. Also, support for v1 and v2 is something that you can get from other ruby gems (most of them refuse to support v3 altogether).

Do one thing and do it well. There's only an interface to interact with an SNMP Agent. Other features like credentials encryption or concurrency are out of the scope of this library, which only guarantees that an SNMP Client is thread-safe and performs ruby-VM-compatible IO. 

## Features

* Client Interface, which supports SNMP 3, 2c, and 1
* Supports get, set, walk and bulk calls. 
* Wrappers for eventmachine and celluloid-io
* Ruby >= 2.0 support
* net-snmp (C library) >= 5.5 support

## Examples

You can use the docker container provided under spec/support to test against these examples. 

```ruby
require 'netsnmp'

manager = NETSNMP::Client.new("localhost", port: 33445, username: "simulator",
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

# SNMP get_bulk
manager.get_bulk("sysOrDescr") do |oid_code, value|
  # do something with them  
  puts "for #{oid_code}: #{value}"
end

manager.close

# SNMP set
manager2 = NETSNMP::Client.new("localhost", port: 33445, username: "simulator",
                                           auth_password: "auctoritas", auth_protocol: :md5, 
                                           priv_password: "privatus", priv_protocol: :des,
                                           context: "0886e1397d572377c17c15036a1e6c66")

# setting to 43, becos yes
manager2.set("sysUpTimeInstance", 43) 

manager2.close
```

## Notes

This library provides support for C net-snmp 5.5 or higher, as this has been considered the most stable SNMP v3 implementation.

To install it in your environment, just use your package manager:

```
# on OSX
> brew install net-snmp  

# Linux
> sudo yum install net-snmp
> sudo apt-get install net-snmp
```

TODO: on Windows(?)

# Contributing

* Fork this repository
* Make your changes and send me a pull request
* If I like them I'll merge them
* If I've accepted a patch, feel free to ask for a commit bit!


