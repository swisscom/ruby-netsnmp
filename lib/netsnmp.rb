# frozen_string_literal: true

require "netsnmp/version"
require "openssl"
require "io/wait"
require "securerandom"
require "ipaddr"

# core structures

begin
  require "xorcist"
  require "xorcist/refinements"
  NETSNMP::StringExtensions = Xorcist::Refinements
rescue LoadError
  # "no xorcist"
  module NETSNMP
    module StringExtensions
      refine String do
        # Bitwise XOR operator for the String class
        def xor(other)
          b1 = unpack("C*")
          return b1 unless other

          b2 = other.unpack("C*")
          longest = [b1.length, b2.length].max
          b1 = [0] * (longest - b1.length) + b1
          b2 = [0] * (longest - b2.length) + b2
          b1.zip(b2).map { |a, b| a ^ b }.pack("C*")
        end
      end
    end
  end
end

require "netsnmp/errors"
require "netsnmp/extensions"
require "netsnmp/loggable"

require "netsnmp/timeticks"

require "netsnmp/oid"
require "netsnmp/varbind"
require "netsnmp/pdu"
require "netsnmp/mib"
require "netsnmp/session"

require "netsnmp/scoped_pdu"
require "netsnmp/v3_session"
require "netsnmp/security_parameters"
require "netsnmp/message"
require "netsnmp/encryption/des"
require "netsnmp/encryption/aes"

require "netsnmp/client"

unless Numeric.method_defined?(:positive?)
  # Ruby 2.3 Backport (Numeric#positive?)
  #
  module PosMethods
    def positive?
      self > 0
    end
  end
  Numeric.__send__(:include, PosMethods)
end

unless String.method_defined?(:+@)
  # Backport for +"", to initialize unfrozen strings from the string literal.
  #
  module LiteralStringExtensions
    def +@
      frozen? ? dup : self
    end
  end
  String.__send__(:include, LiteralStringExtensions)
end
