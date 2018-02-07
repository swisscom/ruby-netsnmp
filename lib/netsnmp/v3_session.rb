# frozen_string_literal: true
module NETSNMP
  # Abstraction for the v3 semantics.
  class V3Session < Session

    # @param [String, Integer] version SNMP version (always 3)
    def initialize(version: 3, context: "", **opts)
      @context = context
      @security_parameters = opts.delete(:security_parameters) 
      super
    end

    # @see {NETSNMP::Session#build_pdu}
    #
    # @return [NETSNMP::ScopedPDU] a pdu
    def build_pdu(type, *vars)
      engine_id = security_parameters.engine_id
      pdu = ScopedPDU.build(type, headers: [engine_id, @context], varbinds: vars)
    end

    # @see {NETSNMP::Session#send}
    def send(*)
      pdu, _ = super
      pdu
    end

    private

    def validate(**options)
      super
      if s = @security_parameters
        # inspect public API
        unless s.respond_to?(:encode) &&
               s.respond_to?(:decode) &&
               s.respond_to?(:sign)   &&
               s.respond_to?(:verify)
          raise Error, "#{s} doesn't respect the sec params public API (#encode, #decode, #sign)" 
        end 
      else
        @security_parameters = SecurityParameters.new(security_level: options[:security_level], 
                                                      username:       options[:username],
                                                      auth_protocol:  options[:auth_protocol],
                                                      priv_protocol:  options[:priv_protocol],
                                                      auth_password:  options[:auth_password],
                                                      priv_password:  options[:priv_password])
  
      end
    end

    # Timeliness is part of SNMP V3 Security
    # The topic is described very nice here https://www.snmpsharpnet.com/?page_id=28
    # https://www.ietf.org/rfc/rfc2574.txt 1.4.1 Timeliness
    # The probe is outdated after 150 seconds which results in a PDU Error, therefore it should expire before that and be renewed
    # The 150 Seconds is specified in https://www.ietf.org/rfc/rfc2574.txt 2.2.3
    def security_parameters
      if @security_parameters.must_revalidate?
        @security_parameters.engine_id = probe_for_engine
      elsif Time.now - @timeliness > 149
        @security_parameters.engine_id = probe_for_engine
      end
      @security_parameters
    end

    # sends a probe snmp v3 request, to get the additional info with which to handle the security aspect
    # Set the timeliness of the probe to ensure the prober expiration after 150 Seconds
    #
    def probe_for_engine
      report_sec_params = SecurityParameters.new(security_level: 0,
                                                 username: @security_parameters.username)
      pdu = ScopedPDU.build(:get, headers: [])
      encoded_report_pdu = Message.encode(pdu, security_parameters: report_sec_params)

      @timeliness = Time.now
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
