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

    def initialize(pdu, options={}) 
      @pdu = pdu
      @encryption = options[:encryption]
      @options = options
    end


    def to_asn(auth_param = AUTHNONE)
      scoped_pdu, priv_param = encode_scoped_pdu
      sec_params = encode_security_parameters_asn(auth_param, priv_param)
      OpenSSL::ASN1::Sequence([ 
        MSG_VERSION, 
        encode_headers_asn,
        OpenSSL::ASN1::OctetString.new(sec_params.to_der),
        scoped_pdu])
    end

    def to_der
      der = to_asn.to_der
      if auth = authentication
        auth_param = OpenSSL::ASN1::OctetString.new(auth.signature(der, @options[:engine_id]))
        der.sub!(AUTHNONE.to_der, auth_param.to_der)
      end 
      der 
    end

    def decode(der)
      asn_tree = OpenSSL::ASN1.decode(der)
      version, headers, security_parameters, pdu_payload = asn_tree.value
      decode_security_parameters_asn(security_parameters.value)

      pdu_der = decode_scoped_pdu(pdu_payload)
      
      @pdu.decode(pdu_der)
    end

    def encryption
      @encryption ||= case @options[:priv_protocol]
      when /des/
        Encryption::DES.new(authentication(password: @options[:priv_password]).localized_key)
      when /aes/
        Encryption::AES.new(authentication(password: @options[:priv_password]).localized_key)
      else
        nil
      end
    end

    def authentication(password: @options[:auth_password], engine_id: @options[:engine_id])
      case options[:auth_protocol]
      when /md5/
        Authentication::MD5.new(password, engine_id)
      when /sha/
        Authentication::SHA.new(password, engine_id)
      else 
        nil 
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

    def encode_security_parameters_asn(auth_param, priv_param)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(@options[:engine_id]),
        OpenSSL::ASN1::Integer.new(@options[:engine_boots]),
        OpenSSL::ASN1::Integer.new(@options[:engine_time]),
        OpenSSL::ASN1::OctetString.new(@options[:username]),
        auth_param,
        priv_param
      ])
    end

    def decode_security_parameters_asn(der)
      asn_tree = OpenSSL::ASN1.decode(der).value

      @options[:engine_id]     = asn_tree[0].value
      @options[:engine_boots]  = asn_tree[1].value.to_i
      @options[:engine_time]   = asn_tree[2].value.to_i
      @options[:username]      = asn_tree[3].value
      @auth_param              = asn_tree[4].value
      @priv_param              = asn_tree[5].value
    end
 
    # @return [Array<OpenSSL::ASN1::ASN1Data, String>] the pdu asn or the encrypted payload, and its salt
    def encode_scoped_pdu
      salt = PRIVNONE 
      pdu_asn = @pdu.to_asn
      if enc = encryption
        pdu_der = pdu_asn.to_der
        enc_pdu, salt_str = enc.encrypt(pdu_der, engine_boots: @options[:engine_boots],
                                                 engine_time: @options[:engine_time])
        pdu_asn = OpenSSL::ASN1::OctetString.new(enc_pdu)
        salt    = OpenSSL::ASN1::OctetString.new(salt_str)
      end
      [ pdu_asn, salt ]
    end

    def decode_scoped_pdu(der)
      pdu_asn = OpenSSL::ASN1.decode(der)
      if enc = encryption and pdu_asn.is_a?(OpenSSL::ASN1::OctetString)
        encrypted_pdu = pdu_asn.value
        decrypted_pdu = enc.decrypt(encrypted_pdu, salt: @priv_param, 
                                                   engine_time: @options[:engine_time],
                                                   engine_boots: @options[:engine_boots])
        pdu_asn = OpenSSL::ASN1.decode(decrypted_pdu)
      end
      pdu_asn
    end

  end
end
