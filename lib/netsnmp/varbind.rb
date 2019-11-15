# frozen_string_literal: true

module NETSNMP
  # Abstracts the PDU variable structure into a ruby object
  #
  class Varbind
    attr_reader :oid, :value

    def initialize(oid, value: nil, type: nil, **_opts)
      @oid = OID.build(oid)
      @type = type
      @value = convert_val(value) if value
    end

    def to_s
      "#<#{self.class}:0x#{object_id.to_s(16)} @oid=#{@oid} @value=#{@value}>"
    end

    def to_der
      to_asn.to_der
    end

    def to_asn
      asn_oid = OID.to_asn(@oid)
      asn_val = if @type
                  convert_to_asn(@type, @value)
                else
                  case @value
                  when String
                    OpenSSL::ASN1::OctetString.new(@value)
                  when Integer
                    OpenSSL::ASN1::Integer.new(@value)
                  when true, false
                    OpenSSL::ASN1::Boolean.new(@value)
                  when nil
                    OpenSSL::ASN1::Null.new(nil)
                  when IPAddr
                    OpenSSL::ASN1::ASN1Data.new(@value.hton, 0, :APPLICATION)
                  when Timetick
                    @value.to_asn
                  else
                    raise Error, "#{@value}: unsupported varbind type"
                  end
                end
      OpenSSL::ASN1::Sequence.new([asn_oid, asn_val])
    end

    def convert_val(asn_value)
      case asn_value
      when OpenSSL::ASN1::OctetString
        # yes, we are forcing all output to UTF-8
        # it's kind of common in snmp, some stuff can't be converted,
        # like Hexa Strings. Parse them into a readable format a la netsnmp
        val = asn_value.value
        begin
          val.encode("UTF-8")
        rescue Encoding::UndefinedConversionError,
               Encoding::ConverterNotFoundError,
               Encoding::InvalidByteSequenceError
          # hexdump me!
          val.unpack("H*")[0].upcase.scan(/../).join(" ")
        end
      when OpenSSL::ASN1::Primitive
        val = asn_value.value
        val = val.to_i if val.is_a?(OpenSSL::BN)
        val
      when OpenSSL::ASN1::ASN1Data
        # application data
        convert_application_asn(asn_value)
      # when OpenSSL::BN
      else
        asn_value # assume it's already primitive
      end
    end

    def convert_to_asn(typ, value)
      asn_type = typ
      asn_val = value
      if typ.is_a?(Symbol)
        asn_type = case typ
                   when :ipaddress then 0
                   when :counter32
                     asn_val = [value].pack("N*")
                     asn_val = asn_val[1..-1] while asn_val[0] == "\x00".b && asn_val[1].unpack("B").first != "1"
                     1
                   when :gauge
                     asn_val = [value].pack("N*")
                     asn_val = asn_val[1..-1] while asn_val[0] == "\x00".b && asn_val[1].unpack("B").first != "1"
                     2
                   when :timetick
                     return Timetick.new(value).to_asn
                   when :opaque then 4
                   when :nsap then 5
                   when :counter64
                     asn_val = [
                       (value >> 96) & 0xFFFFFFFF,
                       (value >> 64) & 0xFFFFFFFF,
                       (value >> 32) & 0xFFFFFFFF,
                       value & 0xFFFFFFFF
                     ].pack("NNNN")
                     asn_val = asn_val[1..-1] while asn_val.start_with?("\x00")
                     6
                   when :uinteger then 7
                   else
                     raise Error, "#{typ}: unsupported application type"
                   end
      end
      OpenSSL::ASN1::ASN1Data.new(asn_val, asn_type, :APPLICATION)
    end

    def convert_application_asn(asn)
      case asn.tag
      when 0 # IP Address
        IPAddr.new_ntoh(asn.value)
      when 1, # ASN counter 32
           2 # gauge
        unpack_32_bit_int(asn.value)
      when 3 # timeticks
        Timetick.new(unpack_32_bit_int(asn.value))
        # when 4 # opaque
        # when 5 # NSAP
      when 6 # ASN Counter 64
        val = asn.value
        val.prepend("\x00") while val.bytesize % 16 != 0
        val.unpack("NNNN").reduce(0) { |sum, elem| (sum << 32) + elem }
        # when 7 # ASN UInteger
      end
    end

    def unpack_32_bit_int(val)
      val.prepend("\x00") while val.bytesize < 4
      directive = "@#{val.bytesize - 4}N*"
      val.unpack(directive)[0] || 0
    end
  end
end
