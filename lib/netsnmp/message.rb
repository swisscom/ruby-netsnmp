module NETSNMP
  # Factory for the SNMP v3 Message format
  class Message
    # TODO: make this random!
    MSG_ID             = OpenSSL::ASN1::Integer.new(56219466)
    AUTHNONE               = OpenSSL::ASN1::OctetString.new("\x00" * 12)
    PRIVNONE               = OpenSSL::ASN1::OctetString.new("")
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3)           # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3)
    MSG_REPORTABLE     = 4

    extend Forwardable 
    def_delegators :@pdu, :add_varbind, :[], :[]=, :varbinds

    attr_reader :pdu, :options

    attr_reader :security_parameters, :engine_id, :engine_boots, :engine_time

    class << self
      def decode(stream, security_parameters: )
        asn_tree = OpenSSL::ASN1.decode(stream)
        version, headers, sec_params, pdu_payload = asn_tree.value

        sec_params_asn = OpenSSL::ASN1.decode(sec_params.value).value

        engine_id, engine_boots, engine_time, username, auth_param, priv_param = sec_params_asn.map(&:value)

        engine_boots=engine_boots.to_i
        engine_time =engine_time.to_i

        encoded_pdu = security_parameters.decode(pdu_payload, salt: priv_param,
                                                              engine_boots: engine_boots,
                                                              engine_time: engine_time)
       
        pdu = ScopedPDU.decode(encoded_pdu) 
        new(pdu, security_parameters: security_parameters,
                 engine_id: engine_id,
                 engine_boots: engine_boots,
                 engine_time: engine_time)
      end


    end

    def initialize(pdu, options={}) 
      @pdu = pdu
      @security_parameters = options[:security_parameters]
      @engine_id = options.fetch(:engine_id, "")
      @engine_time = options.fetch(:engine_time, 0)
      @engine_boots = options.fetch(:engine_boots, 0)
      @options = options
    end


    def to_asn
      scoped_pdu, priv_param = encode_scoped_pdu
      sec_params = encode_security_parameters_asn(priv_param)
      OpenSSL::ASN1::Sequence([ 
        MSG_VERSION, 
        encode_headers_asn,
        OpenSSL::ASN1::OctetString.new(sec_params.to_der),
        scoped_pdu])
    end

    def to_der
      der = to_asn.to_der
      signature = @security_parameters.sign(der)
      if signature 
        auth_param = OpenSSL::ASN1::OctetString.new(signature)
        der.sub!(AUTHNONE.to_der, auth_param.to_der)
      end 
      der 
    end

    def from_message(message)
      pdu.from_pdu(message.pdu)
    end

    private
    def encode_headers_asn
      message_flags = MSG_REPORTABLE | @security_parameters.security_level
      OpenSSL::ASN1::Sequence.new([
        MSG_ID, MSG_MAX_SIZE,
        OpenSSL::ASN1::OctetString.new( [String(message_flags)].pack("h*") ),
        MSG_SECURITY_MODEL
      ])
    end

    def encode_security_parameters_asn(priv_param)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(@engine_id),
        OpenSSL::ASN1::Integer.new(@engine_boots),
        OpenSSL::ASN1::Integer.new(@engine_time),
        OpenSSL::ASN1::OctetString.new(@security_parameters.username),
        AUTHNONE,
        priv_param
      ])
    end
 
    # @return [Array<OpenSSL::ASN1::ASN1Data, String>] the pdu asn or the encrypted payload, and its salt
    def encode_scoped_pdu
      salt = PRIVNONE
      @security_parameters.encode(@pdu, salt: salt, engine_boots: @engine_boots, engine_time: @engine_time)
    end

  end
end
