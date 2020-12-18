# CHANGELOG

## master

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

