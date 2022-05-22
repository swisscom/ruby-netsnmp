# netsnmp

[![Gem Version](https://badge.fury.io/rb/netsnmp.svg)](http://rubygems.org/gems/netsnmp)
![Tests](https://github.com/swisscom/ruby-netsnmp/workflows/Tests/badge.svg)
[![Code Climate](https://codeclimate.com/github/swisscom/ruby-netsnmp/badges/gpa.svg)](https://codeclimate.com/github/swisscom/ruby-netsnmp)
[![Docs](http://img.shields.io/badge/yard-docs-blue.svg)](https://www.rubydoc.info/github/swisscom/ruby-netsnmp/master)

The `netsnmp` gem provides a ruby native implementation of the SNMP protocol (v1/2c abd v3).

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

## Features

This gem provides:

* Implementation in ruby of the SNMP Protocol for v3, v2c and v1 (most notable the rfc3414 and 3826).
* SNMPv3 USM supporting MD5/SHA/SHA256 auth and DES/AES128 privacy crypto algorithms.
* Client/Manager API with simple interface for get, genext, set and walk.
* Pure Ruby.
* Support for concurrency and evented I/O.

## Why?

If you look for snmp gems in ruby toolbox, you'll find a bunch.
You may ask, why not just use one of them?

Most of them only implement v1 and v2, so if your requirement is to use v3, you're left with only 2 choices: [net-snmp](https://github.com/mixtli/net-snmp) (unmantained since 2013) and its follow-up [net-snmp2](https://github.com/jbreeden/net-snmp2), which started as a fork to fix some bugs left unattended. Both libraries wrap the C netsnmp library using FFI, which leaves them vulnerable to the following bugs (experienced in both libraries):

* Dependency of specific versions of netsnmp C package.
* Memory Leaks.
* Doesn't work reliable in ruby > 2.0.0-p576, crashing the VM.
* Network I/O done by the library, thereby blocking the GVL, thereby making all snmp calls block the whole ruby VM.
  * This means, multi-threading is impossible.
  * This means, evented I/O is impossible.

All of these issues are resolved here.

## Features

* Client Interface, which supports SNMP v3, v2c, and v1
* Supports get, getnext, set and walk calls
* MIB support
* Proxy IO object support (for eventmachine/celluloid-io)
* Ruby >= 2.1 support (modern)
* Pure Ruby (no FFI)
* Easy PDU debugging

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
manager.get(oid: "sysName.0") #=> 'tt'

# SNMP walk
# sysORDescr
manager.walk(oid: "sysORDescr").each do |oid_code, value|
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
# sysUpTimeInstance
manager2.set("1.3.6.1.2.1.1.3.0", value: 43)

manager2.close
```

SNMP v2/v1 examples will be similar (beware of the differences in the initialization attributes).

## SNMP Application Types

All previous examples were done specifying primitive types, i.e. unless specified otherwise, it's gonna try to convert a ruby "primitive" type to an ASN.1 primitive type, and vice-versa:

* Integer      -> ASN.1 Integer
* String      -> ASN.1 Octet String
* nil         -> ASN.1 Null
* true, false -> ASN.1 Boolean

That means that, if you pass `value: 43` to the `#set` call, it's going to build a varbind with an ASN.1 Integer. If You issue a `#get` and the response contains an ASN.1 Integer, it's going to return an Integer.

However, SNMP defines application-specific ASN.1 types, for which there is support, albeit limited. Currently, there is support for ip addresses and timeticks.

* IPAddr -> ASN.1 context-specific

If you create an `IPAddr` object (ruby standard library `ipaddr`) and pass it to the `#set` call, it will map to the SNMP content-specific code. If the response of a `#get` call contains an ip address, it will map to an `IPAddr` object.

* NETSNMP::Timeticks -> ASN.1 content-specific

The `NETSNMP::Timeticks` type is internal to this library, but it is a ruby `Numeric` type. You are safe to use it "as a numeric", that is, perform calculations.


Counter32 and Counter64 types will map to plain integers.

You can find usage examples [here](https://github.com/swisscom/ruby-netsnmp/blob/master/spec/varbind_spec.rb). If you need support to a missing type, you have the following options:

* Use the `:type` parameter in `#set` calls:
```ruby
# as a symbol
manager.set("somecounteroid", value: 999999, type: :counter64)
# as the SNMP specific type id, if you're familiar with the protocol
manager.set("somecounteroid", value: 999999, type: 6)
```
* Fork this library, extend support, write a test and submit a PR (the desired solution ;) )

## MIB

`netsnmp` will load the default MIBs from known or advertised (via `MIBDIRS`) directories (provided that they're installed in the system). These will be used for the OID conversion.

Sometimes you'll need to load more, your own MIBs, in which case, you can use the following API:

```ruby
require "netsnmp"

NETSNMP::MIB.load("MY-MIB")
# or, if it's not in any of the known locations
NETSNMP::MIB.load("/path/to/MY-MIB.txt")
```

You can install common SNMP mibs by using your package manager:

```
# using apt-get
> apt-get install snmp-mibs-downloader
# using apk
> apk --update add net-snmp-libs
```

## Concurrency

In ruby, you are usually adviced not to share IO objects across threads. The same principle applies here to `NETSNMP::Client`: provided you use it within a thread of execution, it should behave safely. So, something like this would be possible:

```ruby
general_options = { auth_protocol: ....
routers.map do |r|
  Thread.start do
    NETSNMP::Client.new(general_options.merge(host: r)) do |cl|
      cli.get(oid: "1.6.3.......

    end
  end
end.each(&:join)
```

Evented IO is also supported, in that you can pass a `:proxy` object as an already opened channel of communication to the client. Very important: you have to take care of the lifecycle, as the client will not connect and will not close the object, it will assume no control over it.

When passing a proxy object, you can omit the `:host` parameter.

The proxy object will have to be a duck-type implementing `#send`, which is a method receiving the sending PDU payload, and return the payload of the receiving PDU.

Here is a small pseudo-code example:

```ruby
# beware, we are inside a warp-speed loop!!!
general_options = { auth_protocol: ....
proxy = SpecialUDPImplementation.new(host: router)
NETSNMP::Client.new(general_options.merge(proxy: proxy)) do |cl|
  # this get call will eventually #send to the proxy...
  cli.get(oid: "1.6.3.......

end
# client isn't usable anymore, but now we must close to proxy
proxy.close
```

For more information about this subject, the specs test this feature against celluloid-io. An eventmachine could be added, if someone would be kind enough to provide an implementation.

## Performance


### XOR

This library has some workarounds to some missing features in the ruby language, namely the inexistence of a byte array structure. The closest we have is a byte stream presented as a String with ASCII encoding. A method was added to the String class called `#xor` for some operations needed internally. To prevent needless monkey-patches, Refinements have been employed.

If `#xor` becomes at some point the bottleneck of your usage, this gem has also support for [xorcist](https://github.com/fny/xorcist/). You just have to add it to your Gemfile (or install it in the system):

```
# Gemfile

gem 'netsnmp'

# or, in the command line

$ gem install netsnmp
```

and `netsnmp` will automatically pick it up.

## Auth/Priv Key

If you'll use this gem often with SNMP v3 and auth/priv security level enabled, you'll have that funny feeling that everything could be a bit faster. Well, this is basically because the true performance bottleneck of this gem is the generation of the auth and pass keys used for authorization and encryption. Although this is a one-time thing for each client, its lag will be noticeable if you're running on > 100 hosts.

There is a recommended work-around, but this is only usable **if you are using the same user/authpass/privpass on all the hosts!!!**. Use this with care, then:

```ruby
$shared_security_parameters = NETSNMP::SecurityParameters.new(security_level: :authpriv, username: "mustermann",
                                                              auth_protocol: :md5, priv_protocol: :aes, ....
# this will eager-load the auth/priv_key
...

# over 9000 routers are running on this event loop!!! this is just one!
NETSNMP::Client.new(share_options.merge(proxy: router_proxy, security_parameters: $shared_security_parameters.dup).new do |cl|
  cli.get(oid:  .....
end
```

## Compatibility

This library supports and is tested against ruby versions 2.1 or more recent, including ruby 3. It also supports and tests against Truffleruby.

## OpenSSL

All encoding/decoding/encryption/decryption/digests are done using `openssl`, which is (still) a part of the standard library. If at some point `openssl` is removed and not specifically distributed, you'll have to install it yourself. Hopefully this will never happen.

It also uses the `openssl` ASN.1 API to encode/decode BERs, which is known to be strict, and [may not be able to decode PDUs if not compliant with the supported RFC](https://github.com/swisscom/ruby-netsnmp/issues/47).

## Debugging

You can either set the `NETSNMP_DEBUG` to the desided debug level (currently, 1 and 2). The logs will be written to stderr.

You can also set it for a specific client:

```ruby
manager2 = NETSNMP::Client.new(debug: $stderr, debug_level: 2, ....)
```


## Tests

This library uses RSpec. The client specs are "integration" tests, in that we communicate with an [snmpsim-built snmp agent simulator](https://github.com/etingof/snmpsim).


### RSpec

You can run all tests by typing:

```
> bundle exec rake spec
# or
> bundle exec rspec
...
```


### Docker

The most straightforward way of running the tests is by using the `docker-compose` setup (which is also what's used in the CI). Run it against the ruby version you're targeting:

```
> docker-compose -f docker-compose.yml -f docker-compose-ruby-${RUBY_MAJOR_VERSION}.${RUBY_MAJOR_VERSION}.yml run netsnmp
```

The CI runs the tests against all supported ruby versions. If changes break a specific version of ruby, make sure you commit appropriate changes addressing the edge case, or let me know in the issues board, so I can help.

### SNMP Simulator

The SNMP simulator runs in its own container in the `docker` setup.

You can install the package yourself (ex: `pip install snmpsim`) and run the server locally, and then set the `SNMP_PORT` environment variable, where the snmp simulator is running.

#### CI

The job of the CI is:

* Run all the tests;
* Make sure the tests cover an appropriate surface of the code;
* Lint the code;
* (for ruby 3.0) type check the code;


## Contributing

* Fork this repository
* Make your changes and send me a pull request
* If I like them I'll merge them
* If I've accepted a patch, feel free to ask for a commit bit!

## TODO

There are some features which this gem doesn't support. It was built to provide a client (or manager, in SNMP language) implementation only, and the requirements were fulfilled. However, these notable misses will stand-out:

* No server (Agent, in SNMP-ish) implementation.
* No getbulk support.

So if you like the gem, but would rather have these features implemented, please help by sending us a PR and we'll gladly review it.
