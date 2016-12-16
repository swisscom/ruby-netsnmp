module NETSNMP
  # Factory for the SNMP v3 Message format
  module Message
    extend self
    AUTHNONE               = OpenSSL::ASN1::OctetString.new("\x00" * 12)
    PRIVNONE               = OpenSSL::ASN1::OctetString.new("")
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3)           # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3)
    MSG_REPORTABLE     = 4

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
      [pdu, engine_id, engine_boots, engine_time]
    end

    def encode(pdu, security_parameters: , engine_boots: 0, engine_time: 0)
      scoped_pdu, salt_param = security_parameters.encode(pdu, salt: PRIVNONE, 
                                                               engine_boots: engine_boots, 
                                                               engine_time: engine_time)

      sec_params = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(security_parameters.engine_id),
        OpenSSL::ASN1::Integer.new(engine_boots),
        OpenSSL::ASN1::Integer.new(engine_time),
        OpenSSL::ASN1::OctetString.new(security_parameters.username),
        AUTHNONE,
        salt_param
      ])
      message_flags = MSG_REPORTABLE | security_parameters.security_level
      message_id    = OpenSSL::ASN1::Integer.new(SecureRandom.random_number(2147483647))
      headers = OpenSSL::ASN1::Sequence.new([
        message_id, MSG_MAX_SIZE,
        OpenSSL::ASN1::OctetString.new( [String(message_flags)].pack("h*") ),
        MSG_SECURITY_MODEL
      ])

      encoded = OpenSSL::ASN1::Sequence([ 
        MSG_VERSION, 
        headers,
        OpenSSL::ASN1::OctetString.new(sec_params.to_der),
        scoped_pdu
      ]).to_der
      signature = security_parameters.sign(encoded)
      if signature
        auth_salt = OpenSSL::ASN1::OctetString.new(signature)
        encoded.sub!(AUTHNONE.to_der, auth_salt.to_der)
      end
      encoded
    end

  end
end
