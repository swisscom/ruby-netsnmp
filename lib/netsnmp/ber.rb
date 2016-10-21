# mostly adapted from https://github.com/ruby-ldap/ruby-net-ldap/blob/master/lib/net/ber/core_ext/
require 'stringio'
module NETSNMP
  module BER
    include Core::Constants
    extend self

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


    def encode_sequence(seq, code: 0, internal: 0x30)
      [internal + code].pack("C") << encode_length(seq.length) << seq
    end


    def encode_context(seq, code: 0)
      encode_sequence(seq, code: code, internal: 0xa0) 
    end


    # stream has to implement #getbyte
    # for the sake of simplification (tests), let's assume a full bytestream is already here as array
    def decode(stream, syntax: nil)
      str = stream.respond_to?(:read) ? stream : StringIO.new(stream)
      type = str.getbyte or return nil
      length = decode_length(str) 
      
      object = str.read(length)

      decode_by_asn_type(type, length, object)
    end

    # PRIVATE API
    
    # when the length byte is <127, it's the full one. all others will indicate edge cases
    def decode_length(stream)
      n = stream.getbyte

      if n <= 0x7f
        n
      elsif n == 0x80
        raise Error, "Indeterminate BER length (-1), not implemented"
      elsif n == 0xff
        raise Error, "Invalid BER length 0xFF detected"
      else
        v = 0
        read(n & 0x7f).each_byte do |b|
          v = (v << 8) + b
        end
        v
      end
    end

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
      encoded = String.new(
        raw ? str : if str.respond_to?(:encode)
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
      )
      encoded = encoded.prepend(encode_length(encoded.length))
      encoded = encoded.prepend("\x04")
      encoded
    end

    def encode_length(len)
      if len <= 127
        [len].pack('C')
      else
        i = [len].pack('N').sub(/^[\0]+/, "")
        [0x80 + i.length].pack('C') + i
      end
    end


 
    def decode_by_asn_type(type, length, object)
      case type
        when 0x04, 0x13 # 4 -> octet string, 13 is relative oid
          str = String.new(object)
          if (current_encoding = str.encoding) == Encoding::BINARY # don't touch raw strings
            str.force_encoding("UTF-8")
            str.force_encoding(current_encoding) unless str.valid_encoding?
          end
          type == 13 ? OID.build(str) : str
        when 0x06 # 6 -> ASN Object ID
          oid = object.unpack("w*")
          f = oid[0]
          f < 40 ? [0, f, *oid[1..-1]] :
          f < 80 ? [1, f - 40, *oid[1..-1]] :
                   [2, f - 80, *oid[1..-1]]
        when 0x01 # ASN boolean
          object != "\000"
        when 0x02, 0x10, 0x8a # 2 -> integer, 10 -> sequence, 138 -> 
          neg = !(object.unpack("C").first & 0x80).zero?
          int = 0

          object.each_byte do |b|
            int = (int << 8) + (neg ? 255 - b : b)
          end

          neg ? (int + 1) * -1 : int
        when 0x05
          nil 
        when 0x30, 0x31  # sequence
          Enumerator.new do |y|
            str = StringIO.new(object)
            while (decoded = decode(str)) != nil
              y << decoded
            end
          end
        # out of the primitives
        when SNMP_MSG_GET,
             SNMP_MSG_GETNEXT,
             SNMP_MSG_RESPONSE,
             SNMP_MSG_SET
          [type, object]
        else 
          raise Error, "#{type}: unsupported ASN type"
      end
    end
  end
end
