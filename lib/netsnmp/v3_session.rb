module NETSNMP
  class V3Session < Session

    def build_pdu(type, options=@options)
      pdu = super
      build_message(pdu, options)
    end

    private

    def validate_options(options)
      options = super
      options[:security_level] = case options[:security_level]
        when /no_?auth/         then 0
        when /auth_?no_?priv/   then 1
        when /auth_?priv/, nil  then 3
        when Integer
          options[:security_level]
      end
      options
    end

    def build_message(pdu, options)
      if !@security_parameters
        probe_message = probe_for_engine(pdu, options)
        @security_parameters = SecurityParameters.new(security_level: options[:security_level], 
                                                      username: options[:username],
                                                      engine_id: probe_message.engine_id,
                                                      auth_protocol: options[:auth_protocol],
                                                      priv_protocol: options[:priv_protocol],
                                                      auth_password: options[:auth_password],
                                                      priv_password: options[:priv_password])
        message = Message.new(pdu, options.merge(security_parameters: @security_parameters))
        message.from_message(probe_message)
      else
        message = Message.new(pdu, options.merge(security_parameters: @security_parameters))
      end
      message
    end

    # sends a probe snmp v3 request, to get the additional info with which to handle the security aspect
    #
    # @param [NETSNMP::PDU] pdu the scoped pdu to send
    # @param [Hash] message options
    #
    # @return [NETSNMP::Message] the response snmp v3 message with the agent parameters (engine id, boots, time)
    def probe_for_engine(pdu, options)
      report_sec_params = SecurityParameters.new(security_level: 0,
                                                 username: options[:username])
      message = Message.new(pdu, security_parameters: report_sec_params)
      send(message, options)
    end

    def decode(stream, request, options=@options)
      message = Message.new(PDU.new, options.merge(security_parameters: request.security_parameters))
      message.decode(stream)
      message
    end
  end
end
