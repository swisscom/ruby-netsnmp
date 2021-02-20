# frozen_string_literal: true

module NETSNMP
  # Factory for the SNMP v3 Message format
  class Message
    using ASNExtensions

    AUTHNONE               = OpenSSL::ASN1::OctetString.new("\x00" * 12)
    PRIVNONE               = OpenSSL::ASN1::OctetString.new("")
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3) # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3)
    MSG_REPORTABLE     = 4

    def initialize(debug:, debug_level:)
      @debug = debug
      @debug_level = debug_level
    end

    # @param [String] payload of an snmp v3 message which can be decoded
    # @param [NETSMP::SecurityParameters, #decode] security_parameters knowns how to decode the stream
    #
    # @return [NETSNMP::ScopedPDU] the decoded PDU
    #
    def decode(stream, security_parameters:)
      log { "received encoded V3 message" }
      log { Hexdump.dump(stream) }
      asn_tree = OpenSSL::ASN1.decode(stream)
      log(level: 2) { asn_tree.to_hex }
      _version, _headers, sec_params, pdu_payload = asn_tree.value

      sec_params_asn = OpenSSL::ASN1.decode(sec_params.value).value

      engine_id, engine_boots, engine_time, _username, auth_param, priv_param = sec_params_asn.map(&:value)

      # validate_authentication
      security_parameters.verify(stream.sub(auth_param, AUTHNONE.value), auth_param)

      log { "V3 message has been verified" }
      engine_boots = engine_boots.to_i
      engine_time = engine_time.to_i

      encoded_pdu = security_parameters.decode(pdu_payload, salt: priv_param,
                                                            engine_boots: engine_boots,
                                                            engine_time: engine_time)

      log { "received response PDU" }
      pdu = ScopedPDU.decode(encoded_pdu)
      log(level: 2) { pdu.to_hex }
      [pdu, engine_id, engine_boots, engine_time]
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
                                              OpenSSL::ASN1::OctetString.new([String(message_flags)].pack("h*")),
                                              MSG_SECURITY_MODEL
                                            ])

      encoded = OpenSSL::ASN1::Sequence([
                                          MSG_VERSION,
                                          headers,
                                          OpenSSL::ASN1::OctetString.new(sec_params.to_der),
                                          scoped_pdu
                                        ])
      log(level: 2) { encoded.to_hex }

      encoded = encoded.to_der
      log { Hexdump.dump(encoded) }
      signature = security_parameters.sign(encoded)
      if signature
        log { "signing V3 message..." }
        auth_salt = OpenSSL::ASN1::OctetString.new(signature)
        encoded.sub!(AUTHNONE.to_der, auth_salt.to_der)
        log { Hexdump.dump(encoded) }
      end
      encoded
    end

    private

    COLORS = {
      black: 30,
      red: 31,
      green: 32,
      yellow: 33,
      blue: 34,
      magenta: 35,
      cyan: 36,
      white: 37
    }.freeze

    def log(level: @debug_level, color: nil)
      return unless @debug
      return unless @debug_level >= level

      debug_stream = @debug

      message = (+"\n" << yield << "\n")
      message = "\e[#{COLORS[color]}m#{message}\e[0m" if debug_stream.respond_to?(:isatty) && debug_stream.isatty
      debug_stream << message
    end
  end
end
