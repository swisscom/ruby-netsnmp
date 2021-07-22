# CHANGELOG

## master

### 0.6.0

#### Features

`netsnmp` supports SHA256 as an authentication protocol. You can pass `:sha256` to the `:auth_protocol` argument, as an alternative too `:sha` or `:md5`. (#29)

### 0.5.0

#### Improvements

* Using the `sendmsg` and `recvmsg` family of socket APIs, which allow for connectionless-oriented communication, and do not require the response packets coming from the same host:port pair (which some old SNMP agents do).

#### Bugfixes

* Fixed corruption of authenticated PDUs when performing auth param substitution in the payload, which was reported as causinng decryption error report PDUs being sent back.

### 0.4.2

#### Improvements

Errors of the [usmStats family](http://oidref.com/1.3.6.1.6.3.15.1.1) will now raise an exception, where the message will be the same as `netsnmp` message for the same use-case (#50).

### 0.4.1

fixed: namespace scope-based MIB lookups weren't working for custom-loaded MIBs (#48)

### 0.4.0

#### Features

* New debugging logs: `NETSNMP::Client.new(..., debug: $stderr, debug_level: 2)` (can also be activated with envvar, i.e. `NETSNMP_DEBUG=2`);

#### Improvements

* octet strings are now returned in the original encoding; Binary strings are now returned as an "hex-string", which will be a normal string, but it'll print in hexa format, a la netsnmp.

#### Bugfixes

* incoming v3 message security level is now used to decide whether to decrypt/authorize (it was taking the send security level into account);
* reacting to incoming REPORT pdu with `IdNotInTimeWindow` OID by updating the time and replay request PDU (something common to Cisco Routers);
* Fiterling out unused bits from V3 message flags;

### 0.3.0

* MIB Parser.
* methods can use MIBs as well as OIDs.

```ruby
client.get(oid: "sysName.0")
```

### 0.2.0

* Fix kwargs issues, enabling ruby 3.
* RBS type signatures.
* Bye Travis, hello Github Actions.

### 0.1.9

* Fix the encoding of gauge/counter32 ASN values.

### 0.1.8

* Fix for Timeticks with smaller values.

### 0.1.7

* Fixed padding of counter/gauge varbinds.

### 0.1.6

* Added support for 64bit varbinds, such as Counter64.

### 0.1.5

* Added `NETSNMP#inform` to send INFORM PDUs as well.
* Fixed encoding for counter32/gauge types for >16bit numbers.
* Fixed encryption of PDU packets when data's not a multiplier of 8.

### 0.1.4

* Fixed unexisting `Timeout::Error` constant, as "timeout" wasn't being required.
* Allow returning multiple varbind values, when more than one PDU is sent.
* Added proper support for Gauge/Counter32.
* Added support for SNMPv3 timeliness.

### 0.1.3

* Added the `NETSNMP::Timetick` entity, which coerces into a numeric.

### 0.1.2

* Fixes for propagation of error, specific error message for unrecognized SNMP error codes as well.
* encode octet strings to UTF-8

### 0.1.1

* IPAddress varbind values will be converted from and to `IPAddr` objects.

### 0.1.0

* `netsnmp` gem goes public.
* rewrite of FFI logic into pure ruby, handling ASN1 encoding via `openssl` gem.

### 0.0.2

* Fixing timeout issues.

### 0.0.1

* First version, FFI-based (using C `libnetsnmp`).
* (This version was very buggy, and isn't recommended for production usage).
