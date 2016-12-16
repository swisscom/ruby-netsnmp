# frozen_string_literal: true
require "netsnmp/version"
require "openssl"
require "io/wait"
require "securerandom"


# CORE EXTENSIONS!!!!!
# TODO: replace this with fast_xor



# core structures
require "netsnmp/logger"

module NETSNMP
  module StringExtensions
    refine String do
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
  end
end

require "netsnmp/errors"

require "netsnmp/oid"
require "netsnmp/varbind"
require "netsnmp/pdu"
require "netsnmp/session"

require "netsnmp/scoped_pdu"
require "netsnmp/v3_session"
require "netsnmp/security_parameters"
require "netsnmp/message"
require "netsnmp/encryption/des"
require "netsnmp/encryption/aes"

require "netsnmp/client"
