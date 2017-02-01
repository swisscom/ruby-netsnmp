# frozen_string_literal: true
module NETSNMP
  # Abstracts the PDU variable structure into a ruby object
  #
  class Varbind

    attr_reader :oid, :value

    def initialize(oid , value: nil, type: nil, **opts)
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
        asn_type, asn_val = convert_to_asn(@type, @value)
        OpenSSL::ASN1::ASN1Data.new(asn_val, asn_type, :APPLICATION)
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
        else
          raise Error, "#{@value}: unsupported varbind type"
        end
      end
      OpenSSL::ASN1::Sequence.new( [asn_oid, asn_val] )
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
      when OpenSSL::BN
      else
       asn_value # assume it's already primitive
      end 
    end

    def convert_to_asn(typ, value)
      return [typ, value] unless typ.is_a?(Symbol)
      case typ
        when :ipaddress then 0
        when :counter32 then 1
        when :gauge then 2
        when :timetick then [3, [ value].pack("N") ]
        when :opaque then 4
        when :nsap then 5
        when :counter64 then 6
        when :uinteger then 7
      end
    end

    def convert_application_asn(asn)
      case asn.tag
        when 0 # IP Address
          IPAddr.new_ntoh(asn.value)
        when 1 # ASN counter 32
          asn.value.unpack("n*")[0] || 0
        when 2 # gauge
        when 3 # timeticks
          asn.value.unpack("N*")[0] || 0
        when 4 # opaque
        when 5 # NSAP
        when 6 # ASN Counter 64
        when 7 # ASN UInteger
      end
    end
  end
end
