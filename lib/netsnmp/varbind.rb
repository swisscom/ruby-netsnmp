# frozen_string_literal: true
module NETSNMP
  # Abstracts the PDU variable structure into a ruby object
  #
  class Varbind

    attr_reader :oid, :value

    def initialize(oid , value: nil, type: nil)
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
          OpenSSL::ASN1::OctetString
        when Integer
          OpenSSL::ASN1::Integer
        when true, false
          OpenSSL::ASN1::Boolean
        when nil
          OpenSSL::ASN1::Null
        else
          raise Error, "#{@value}: unsupported varbind type"
        end.new(@value)
      end
      OpenSSL::ASN1::Sequence.new( [asn_oid, asn_val] )
    end


    def convert_val(asn_value)
      case asn_value
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
