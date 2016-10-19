# mostly adapted from https://github.com/ruby-ldap/ruby-net-ldap/blob/master/lib/net/ber/core_ext/integer.rb
module NETSNMP
  module BER
    extend self

    # PUBLIC API

    def encode(obj)
      case obj
      when Integer then encode_integer(obj)
      end
    end



    # PRIVATE API

    
    def encode_integer(integer)
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
      code = result.pack('C*')
      code.prepend("\x02") # encoded type
      code
    end

    def encode_string(str)

    end

    def encode_null

    end

    def encode_oid(oid)

    end
  end
end
