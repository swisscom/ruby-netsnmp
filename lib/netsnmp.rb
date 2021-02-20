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

module NETSNMP
  module IsNumericExtensions
    refine String do
      def integer?
        each_byte do |byte|
          return false unless byte >= 48 && byte <= 57
        end
        true
      end
    end
  end

  module StringExtensions
    # If you wonder why this is there: the oauth feature uses a refinement to enhance the
    # Regexp class locally with #match? , but this is never tested, because ActiveSupport
    # monkey-patches the same method... Please ActiveSupport, stop being so intrusive!
    # :nocov:
    refine(String) do
      def match?(*args)
        !match(*args).nil?
      end
    end
  end

  module ASNExtensions
    ASN_COLORS = {
      OpenSSL::ASN1::Sequence => 34, # blue
      OpenSSL::ASN1::OctetString => 32, # green
      OpenSSL::ASN1::Integer => 33, # yellow
      OpenSSL::ASN1::ObjectId => 35, # magenta
      OpenSSL::ASN1::ASN1Data => 36 # cyan
    }.freeze

    DEMODULIZE = ->(klass) { klass.name.split("::").last }
    COLORIZE = lambda do |asn, der = asn.to_der|
      hex = Hexdump.dump(der, separator: " ")
      "#{DEMODULIZE[asn.class]}: \e[#{ASN_COLORS[asn.class]}m#{hex}\e[0m"
    end

    # basic types
    ASN_COLORS.each_key do |klass|
      refine(klass) do
        def to_hex
          "#{COLORIZE[self]} (#{value.to_s.inspect})"
        end
      end
    end

    # composite types
    refine(OpenSSL::ASN1::Sequence) do
      def to_hex
        values = value.map(&:to_der).join
        hex_values = value.map(&:to_hex).map { |s| s.sub("\t", "\t\t") }.map { |s| "\n\t#{s}" }.join
        der = to_der
        der = der.sub(values, "")

        "#{COLORIZE[self, der]}#{hex_values}"
      end
    end

    refine(OpenSSL::ASN1::ASN1Data) do
      def to_hex
        case value
        when Array
          values = value.map(&:to_der).join
          hex_values = value.map(&:to_hex).map { |s| s.sub("\t", "\t\t") }.map { |s| "\n\t#{s}" }.join
          der = to_der
          der = der.sub(values, "")
        else
          der = to_der
          hex_values = nil
        end

        "#{COLORIZE[self, der]}#{hex_values}"
      end
    end
  end

  def self.debug=(io)
    @debug_output = io
  end

  def self.debug(&blk)
    @debug_output << blk.call + "\n" if @debug_output
  end

  unless defined?(Hexdump) # support the hexdump gem
    module Hexdump
      def self.dump(data, width: 8, separator: "\n")
        pairs = data.unpack("H*").first.scan(/.{4}/)
        pairs.each_slice(width).map do |row|
          row.join(" ")
        end.join(separator)
      end
    end
  end
end

require "netsnmp/errors"

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
