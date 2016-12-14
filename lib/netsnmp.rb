require "netsnmp/version"
require "openssl"
require "socket"
require "io/wait"
require "securerandom"


# CORE EXTENSIONS!!!!!
# TODO: replace this with fast_xor
class String
  # Bitwise XOR operator for the String class
  def xor( other )
    b1 = self.unpack("C*")
    return b1 if !other

    b2 = other.unpack("C*")
    longest = [b1.length,b2.length].max
    b1 = [0]*(longest-b1.length) + b1
    b2 = [0]*(longest-b2.length) + b2
    b1.zip(b2).map{ |a,b| a^b }.pack("C*")
  end
end


# core structures
require "netsnmp/logger"
require 'netsnmp/core'

module NETSNMP
  # @return [String] the version of the netsnmp C library
  def self.version ; Core.version ; end
end

require "netsnmp/ber"
require "netsnmp/errors"
require "netsnmp/varbind"
require "netsnmp/oid"
require "netsnmp/pdu"
require "netsnmp/session"


require "netsnmp/message"
require "netsnmp/encryption/des"
require "netsnmp/encryption/aes"
require "netsnmp/authentication/md5"
require "netsnmp/authentication/sha"

require "netsnmp/client"
