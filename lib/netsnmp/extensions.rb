# frozen_string_literal: true

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
    refine(String) do
      unless String.method_defined?(:match?)
        def match?(*args)
          !match(*args).nil?
        end
      end

      unless String.method_defined?(:unpack1)
        def unpack1(format)
          unpack(format).first
        end
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

    # basic types
    ASN_COLORS.each_key do |klass|
      refine(klass) do
        def to_hex
          "#{colorize_hex} (#{value.to_s.inspect})"
        end
      end
    end

    # composite types
    refine(OpenSSL::ASN1::Sequence) do
      def to_hex
        values = value.map(&:to_der).join
        hex_values = value.map(&:to_hex).map { |s| s.gsub(/(\t+)/) { "\t#{Regexp.last_match(1)}" } }.map { |s| "\n\t#{s}" }.join
        der = to_der
        der = der.sub(values, "")

        "#{colorize_hex(der)}#{hex_values}"
      end
    end

    refine(OpenSSL::ASN1::ASN1Data) do
      attr_reader :label

      def with_label(label)
        @label = label
        self
      end

      def to_hex
        case value
        when Array
          values = value.map(&:to_der).join
          hex_values = value.map(&:to_hex)
                            .map { |s| s.gsub(/(\t+)/) { "\t#{Regexp.last_match(1)}" } }
                            .map { |s| "\n\t#{s}" }.join
          der = to_der
          der = der.sub(values, "")
        else
          der = to_der
          hex_values = nil
        end

        "#{colorize_hex(der)}#{hex_values}"
      end

      private

      def colorize_hex(der = to_der)
        hex = Hexdump.dump(der, separator: " ")
        lbl = @label || self.class.name.split("::").last
        "#{lbl}: \e[#{ASN_COLORS[self.class]}m#{hex}\e[0m"
      end
    end
  end

  module Hexdump
    using StringExtensions

    def self.dump(data, width: 8, in_groups_of: 4, separator: "\n")
      pairs = data.unpack1("H*").scan(/.{#{in_groups_of}}/)
      pairs.each_slice(width).map do |row|
        row.join(" ")
      end.join(separator)
    end
  end

  # Like a string, but it prints an hex-string version of itself
  class HexString < String
    def inspect
      Hexdump.dump(self, in_groups_of: 2, separator: " ")
    end
  end
end
