# frozen_string_literal: true
module NETSNMP
  class V3Session < Session

    def initialize(*)
      super
      @security_parameters = @options.delete(:security_parameters)
    end

    def build_pdu(type, *oids)
      engine_id = security_parameters.engine_id
      context   = @options.fetch(:context, "")
      pdu = ScopedPDU.build(type, headers: [engine_id, context], varbinds: oids)
    end

    def send(*)
      pdu, _ = super
      pdu
    end

    private

    def validate_options(options)
      options = super
      if s = @security_parameters
        # inspect public API
        unless s.respond_to?(:encode) &&
               s.respond_to?(:decode) &&
               s.respond_to?(:sign)   &&
               s.respond_to?(:verify)
          raise Error, "#{s} doesn't respect the sec params public API (#encode, #decode, #sign)" 
        end 
      end
      options
    end

    def security_parameters
      @security_parameters ||= SecurityParameters.new(security_level: @options[:security_level], 
                                                      username: @options[:username],
                                                      auth_protocol: @options[:auth_protocol],
                                                      priv_protocol: @options[:priv_protocol],
                                                      auth_password: @options[:auth_password],
                                                      priv_password: @options[:priv_password])
      if @security_parameters.engine_id.empty?
        @security_parameters.engine_id = probe_for_engine
      end
      @security_parameters
    end

    # sends a probe snmp v3 request, to get the additional info with which to handle the security aspect
    #
    def probe_for_engine
      report_sec_params = SecurityParameters.new(security_level: 0,
                                                 username: @security_parameters.username)
      pdu = ScopedPDU.build(:get, headers: [])
      encoded_report_pdu = Message.encode(pdu, security_parameters: report_sec_params)

      encoded_response_pdu = @transport.send(encoded_report_pdu)

      _, engine_id, @engine_boots, @engine_time = decode(encoded_response_pdu, security_parameters: report_sec_params)
      engine_id
    end

    def encode(pdu)
      Message.encode(pdu, security_parameters: @security_parameters, 
                          engine_boots: @engine_boots,
                          engine_time: @engine_time)
    end

    def decode(stream, security_parameters: @security_parameters)
      Message.decode(stream, security_parameters: security_parameters)
    end
  end
end
