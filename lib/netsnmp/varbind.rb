module NETSNMP
  # Abstracts the PDU variable structure into a ruby object
  #
  class Varbind
    Error = Class.new(Error)

    attr_reader :oid, :value

    # @param [FFI::Pointer] pointer to the variable list
    def initialize(oid , value: nil)
      @oid = oid.is_a?(OID) ? oid : OID.build(oid)
      @value = value
    end

    def oid_code
      @oid.code.to_s
    end

    def to_ber
      to_asn.to_der
    end

    def to_asn
      asn_oid = @oid.to_asn
      asn_val = case @value
        when String
          OpenSSL::ASN1::OctetString
        when Integer
          OpenSSL::ASN1::Integer
        when true, false
          OpenSSL::ASN1::Boolean
        when nil
          OpenSSL::ASN1::Null
        else
          raise Error, "#{@value}: unsupported type"
      end.new(@value)
      OpenSSL::ASN1::Sequence.new( [asn_oid, asn_val] )
    end
  end
end
