module NETSNMP
  # Factory for the SNMP v3 Message format
  class Message
    # TODO: make this random!
    MSG_ID             = OpenSSL::ASN1::Integer.new(56219466)
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3)           # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3)
    MSG_REPORTABLE     = 4

    extend Forwardable 
    def_delegators :@pdu, :add_varbind, :[], :[]=, :varbinds

    attr_reader :pdu, :options

    def initialize(options={}) 
      @pdu = options.delete(:pdu)
      @options = options

      @priv_param = encryption.salt
    end


    def to_asn(auth_param = "\x00" * 12)
      sec_params = encode_security_parameters_asn(auth_param)
      OpenSSL::ASN1::Sequence([ 
        MSG_VERSION, 
        encode_headers_asn,
        OpenSSL::ASN1::OctetString.new(sec_params.to_der),
        scoped_pdu])
    end

    def to_der
      der = to_asn.to_der
      if auth = authentication
        auth_param = auth.generate_param(der, @options[:engine_id])
        der = to_asn(auth_param).to_der
      end 
      der 
    end

    def decode(der)
      asn_tree = OpenSSL::ASN1.decode(der)
      version, headers, security_parameters, pdu_payload = asn_tree.value
      decode_security_parameters_asn(security_parameters.value)

      pdu_der = encryption.decrypt(pdu_payload, @priv_param)
      
      @pdu = PDU.new
      @pdu.decode(pdu_der)
    end

    def encryption
      case options[:priv_protocol]
      when /des/
        Encryption::DES.new(options[:priv_password], options[:engine_boots])
      when /aes/
        raise
      else
        Encryption::None.new
      end
    end

    def authentication
      case options[:auth_protocol]
      when /md5/
        Authentication::MD5.new(options[:auth_password])
      when /aes/
        raise
      end
    end

    def from_message(message)
      @options[:engine_id] = message.options[:engine_id]
      @options[:engine_boots] = message.options[:engine_boots]
      @options[:engine_time] = message.options[:engine_time]
      pdu.from_pdu(message.pdu)
    end

    private
    def encode_headers_asn
      message_flags = MSG_REPORTABLE | (@options[:security_level] || 0)
      OpenSSL::ASN1::Sequence.new([
        MSG_ID, MSG_MAX_SIZE,
        OpenSSL::ASN1::OctetString.new( [String(message_flags)].pack("h*") ),
        MSG_SECURITY_MODEL
      ])
    end

    def encode_security_parameters_asn(auth_param)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(@options[:engine_id]),
        OpenSSL::ASN1::Integer.new(@options[:engine_boots]),
        OpenSSL::ASN1::Integer.new(@options[:engine_time]),
        OpenSSL::ASN1::OctetString.new(@options[:username]),
        OpenSSL::ASN1::OctetString.new(auth_param),
        OpenSSL::ASN1::OctetString.new(@priv_param)
      ])
    end

    def decode_security_parameters_asn(der)
      asn_tree = OpenSSL::ASN1.decode(der).value

      @options[:engine_id] = asn_tree[0].value
      @options[:engine_boots] = asn_tree[1].value.to_i
      @options[:engine_time] = asn_tree[2].value.to_i
      @options[:username] = asn_tree[3].value
    end

    def scoped_pdu
      encryption.encrypt(@pdu)
    end

    def authenticate(engineid)
      authentication.generate_param(engineid)
    end
  end
end
