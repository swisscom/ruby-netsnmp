module NETSNMP
  class V3Session < Session

    def build_pdu(type, *oids)
      engine_id = @options.fetch(:engine_id, "")
      context   = @options.fetch(:context)
      pdu = ScopedPDU.build(type, headers: [engine_id, context], varbinds: oids)
      build_message(pdu)
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

    def build_message(pdu)
      if !@security_parameters
        probe_message = probe_for_engine(pdu)
        @options[:engine_id] = probe_message.engine_id
        @security_parameters = SecurityParameters.new(security_level: @options[:security_level], 
                                                      username: @options[:username],
                                                      engine_id: probe_message.engine_id,
                                                      auth_protocol: @options[:auth_protocol],
                                                      priv_protocol: @options[:priv_protocol],
                                                      auth_password: @options[:auth_password],
                                                      priv_password: @options[:priv_password])
        message = Message.new(pdu, security_parameters: @security_parameters,
                                   engine_id: probe_message.engine_id,
                                   engine_boots: probe_message.engine_boots,
                                   engine_time: probe_message.engine_time)
        message.from_message(probe_message)
      else
        message = Message.new(pdu, security_parameters: @security_parameters)
      end
      message
    end

    # sends a probe snmp v3 request, to get the additional info with which to handle the security aspect
    #
    def probe_for_engine(pdu)
      report_sec_params = SecurityParameters.new(security_level: 0,
                                                 username: @options[:username])
      message = Message.new(pdu, security_parameters: report_sec_params)
      send(message)
    end

    def decode(stream, request)
      Message.decode(stream, security_parameters: request.security_parameters)
    end
  end
end
