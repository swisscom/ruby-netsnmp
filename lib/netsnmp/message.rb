# frozen_string_literal: true

module NETSNMP
  # Factory for the SNMP v3 Message format
  class Message
    using ASNExtensions

    prepend Loggable

    AUTHNONE               = OpenSSL::ASN1::OctetString.new("\x00" * 12).with_label(:auth_mask)
    PRIVNONE               = OpenSSL::ASN1::OctetString.new("")
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507).with_label(:max_message_size)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3).with_label(:security_model) # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3).with_label(:message_version)
    MSG_REPORTABLE     = 4

    def initialize(**); end

    def verify(stream, auth_param, security_level, security_parameters:)
      security_parameters.verify(stream.sub(auth_param, AUTHNONE.value), auth_param, security_level: security_level)
    end

    # @param [String] payload of an snmp v3 message which can be decoded
    # @param [NETSMP::SecurityParameters, #decode] security_parameters knowns how to decode the stream
    #
    # @return [NETSNMP::ScopedPDU] the decoded PDU
    #
    def decode(stream, security_parameters:)
      log { "received encoded V3 message" }
      log { Hexdump.dump(stream) }
      asn_tree = OpenSSL::ASN1.decode(stream).with_label(:v3_message)

      version, headers, sec_params, pdu_payload = asn_tree.value
      version.with_label(:message_version)
      headers.with_label(:headers)
      sec_params.with_label(:security_params)
      pdu_payload.with_label(:pdu)

      _, _, message_flags, = headers.value

      # get last byte
      # discard the left-outermost bits and keep the remaining two
      security_level = message_flags.with_label(:message_flags).value.unpack("C*").last & 3

      sec_params_asn = OpenSSL::ASN1.decode(sec_params.value).with_label(:security_params)

      engine_id, engine_boots, engine_time, username, auth_param, priv_param = sec_params_asn.value
      engine_id.with_label(:engine_id)
      engine_boots.with_label(:engine_boots)
      engine_time.with_label(:engine_time)
      username.with_label(:username)
      auth_param.with_label(:auth_param)
      priv_param.with_label(:priv_param)

      log(level: 2) { asn_tree.to_hex }
      log(level: 2) { sec_params_asn.to_hex }

      auth_param = auth_param.value

      engine_boots = engine_boots.value.to_i
      engine_time = engine_time.value.to_i

      encoded_pdu = security_parameters.decode(pdu_payload, salt: priv_param.value,
                                                            engine_boots: engine_boots,
                                                            engine_time: engine_time,
                                                            security_level: security_level)

      log { "received response PDU" }
      pdu = ScopedPDU.decode(encoded_pdu)
      pdu.auth_param = auth_param
      pdu.security_level = security_level

      log(level: 2) { pdu.to_hex }
      [pdu, engine_id.value, engine_boots, engine_time]
    end

    # @param [NETSNMP::ScopedPDU] the PDU to encode in the message
    # @param [NETSMP::SecurityParameters, #decode] security_parameters knowns how to decode the stream
    #
    # @return [String] the byte representation of an SNMP v3 Message
    #
    def encode(pdu, security_parameters:, engine_boots: 0, engine_time: 0)
      log(level: 2) { pdu.to_hex }
      log { "encoding PDU in V3 message..." }
      scoped_pdu, salt_param = security_parameters.encode(pdu, salt: PRIVNONE,
                                                               engine_boots: engine_boots,
                                                               engine_time: engine_time)

      sec_params = OpenSSL::ASN1::Sequence.new([
                                                 OpenSSL::ASN1::OctetString.new(security_parameters.engine_id).with_label(:engine_id),
                                                 OpenSSL::ASN1::Integer.new(engine_boots).with_label(:engine_boots),
                                                 OpenSSL::ASN1::Integer.new(engine_time).with_label(:engine_time),
                                                 OpenSSL::ASN1::OctetString.new(security_parameters.username).with_label(:username),
                                                 AUTHNONE,
                                                 salt_param
                                               ]).with_label(:security_params)
      log(level: 2) { sec_params.to_hex }

      message_flags = MSG_REPORTABLE | security_parameters.security_level
      message_id    = OpenSSL::ASN1::Integer.new(SecureRandom.random_number(2147483647)).with_label(:message_id)
      headers = OpenSSL::ASN1::Sequence.new([
                                              message_id,
                                              MSG_MAX_SIZE,
                                              OpenSSL::ASN1::OctetString.new([String(message_flags)].pack("h*")).with_label(:message_flags),
                                              MSG_SECURITY_MODEL
                                            ]).with_label(:headers)

      encoded = OpenSSL::ASN1::Sequence([
                                          MSG_VERSION,
                                          headers,
                                          OpenSSL::ASN1::OctetString.new(sec_params.to_der).with_label(:security_params),
                                          scoped_pdu
                                        ]).with_label(:v3_message)
      log(level: 2) { encoded.to_hex }

      encoded = encoded.to_der
      log { Hexdump.dump(encoded) }
      signature = security_parameters.sign(encoded)
      if signature
        log { "signing V3 message..." }
        auth_salt = OpenSSL::ASN1::OctetString.new(signature).with_label(:auth)
        log(level: 2) { auth_salt.to_hex }
        none_der = AUTHNONE.to_der
        encoded[encoded.index(none_der), none_der.size] = auth_salt.to_der
        log { Hexdump.dump(encoded) }
      end
      encoded
    end
  end
end
