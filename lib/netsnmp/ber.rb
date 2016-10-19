# mostly adapted from https://github.com/ruby-ldap/ruby-net-ldap/blob/master/lib/net/ber/core_ext/
module NETSNMP
  module BER
    extend self

    # PUBLIC API

    def encode(obj, **opts)
      case obj
      when String
        encode_string(obj, **opts)
      when Integer 
        encode_integer(obj, **opts)
      when true # http://tools.ietf.org/html/rfc4511#section-5.1
        "\001\001\xFF".force_encoding("ASCII-8BIT")
      when false
        "\001\001\000"
      when nil
        "\005\000"
      end
    end

    # PRIVATE API
    
    def encode_integer(integer, code: "\x02")
      # Compute the byte length, accounting for negative values requiring two's
      # complement.
      size  = 1
      size += 1 until (((integer < 0) ? ~integer : integer) >> (size * 8)).zero?

      # Padding for positive, negative values. See section 8.5 of ITU-T X.690:
      # http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf

      # For positive integers, if most significant bit in an octet is set to one,
      # pad the result (otherwise it's decoded as a negative value).

      if integer > 0 && (integer & (0x80 << (size - 1) * 8)) > 0
        size += 1
      end

      # And for negative integers, pad if the most significant bit in the octet
      # is not set to one (othwerise, it's decoded as positive value).
      if integer < 0 && (integer & (0x80 << (size - 1) * 8)) == 0
        size += 1
      end

      # Store the size of the Integer in the result
      result = [size]

      # Appends bytes to result, starting with higher orders first. Extraction
      # of bytes is done by right shifting the original Integer by an amount
      # and then masking that with 0xff.
      while size > 0
        # right shift size - 1 bytes, mask with 0xff
        result << ((integer >> ((size - 1) * 8)) & 0xff)
        size -= 1
      end
      result = result.pack('C*')
      result.prepend(code) # encoded type
      result
    end

    # @param [true, false] raw false by default; set to true if you don't want to encode 
    #   the string to utf8
    def encode_string(str, code: "0x04", raw: false)
      encoded = raw ? str : if str.respond_to?(:encode)
        begin
          str.encode('UTF-8').force_encoding('ASCII-8BIT')
        rescue Encoding::UndefinedConversionError
          str
        rescue Encoding::ConverterNotFoundError
          str
        rescue Encoding::InvalidByteSequenceError
          str
        end
      end 
      encoded = encoded.prepend(encode_length(encoded.length))
      encoded = encoded.prepend("\x04")
      encoded
    end

    def encode_null

    end

    def encode_oid(oid)

    end

    def encode_length(len)
      if len <= 127
        [len].pack('C')
      else
        i = [len].pack('N').sub(/^[\0]+/, "")
        [0x80 + i.length].pack('C') + i
      end
    end
  end
end
