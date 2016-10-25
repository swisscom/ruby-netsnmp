module NETSNMP
  # Factory for the SNMP v3 Message format
  class Message
    MSG_ID             = OpenSSL::ASN1::Integer.new(56219466)
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3)           # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3)
    MSG_REPORTABLE     = 4

    def initialize(pdu, **options) 
      @pdu = pdu
      @options = options

      @auth_param = options[:auth_param] || ("\x00" * 12)
      @priv_param = options[:priv_param] || ""
    end

    def to_asn
      OpenSSL::ASN1::Sequence([ 
        MSG_VERSION, 
        headers_asn,
        OpenSSL::ASN1::OctetString.new(security_parameters_asn.to_der),
        @pdu])
    end

    def to_der
      to_asn.to_der
    end

    private
    def headers_asn
      message_flags = MSG_REPORTABLE | (@options[:security_level] || 0)
      OpenSSL::ASN1::Sequence.new([
        MSG_ID, MSG_MAX_SIZE,
        OpenSSL::ASN1::OctetString.new( [String(message_flags)].pack("h*") ),
        MSG_SECURITY_MODEL
      ])
    end

    def security_parameters_asn
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(@options[:engine_id]),
        OpenSSL::ASN1::Integer.new(@options[:engine_boots]),
        OpenSSL::ASN1::Integer.new(@options[:engine_time]),
        OpenSSL::ASN1::OctetString.new(@options[:username]),
        OpenSSL::ASN1::OctetString.new(@auth_param),
        OpenSSL::ASN1::OctetString.new(@priv_param)
      ])
    end
  end
end
