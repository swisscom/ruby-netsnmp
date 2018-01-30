# frozen_string_literal: true

require 'netsnmp'
require 'logger'

module NETSNMP

  # Provides a base class for building SNMP Managers
  #
  # Does not implement a transport so must be subclassed
  #
  #
  class Manager
    V1_Trap = 4
    Inform = 6
    V2_Trap = 7

    def initialize(logger = Logger.new(STDOUT))
      @logger = logger
      @communities = {}
      @security = {}
      @boots = Time.now.to_i
    end

    attr_reader :boots, :logger

    # Returns the time in seconds since the Agent booted
    #
    # @return [Integer] the time in seconds since boot
    #
    def v3_time
      Time.now.to_i - @boots
    end

    # Process raw data coming off the network transport
    #
    # @param [String] data the raw message data
    # @param [Object] ip the IP address (in the format you expect for the transport)
    # @param [Integer] port the port the remote client is communicating on
    #
    def add_community(handler, name: "public")
      @communities[name] = handler

      if handler.respond_to? :security_parameters
        params = handler.security_parameters
        security = case params
        when ::Hash
          params[:engine_id] ||= name
          SecurityParameters.new(params)
        when SecurityParameters
          params
        when nil
          nil
        else
          raise "unsupported security parameters"
        end

        if security
          @communities[security.engine_id] ||= handler
          @security[security.engine_id] = security
        end
      end
    end

    # Process raw data coming off the network transport
    #
    # @param [String] data the raw message data
    # @param [Object] ip the IP address (in the format you expect for the transport)
    # @param [Integer] port the port the remote client is communicating on
    #
    def new_message(data, ip, port)
      # Grab the message version
      asn_tree = OpenSSL::ASN1.decode(data)
      headers = asn_tree.value
      version = headers[0].value

      # Extract the community / engine id to look up the appropriate handler
      if version == 3
        sec_params_asn = OpenSSL::ASN1.decode(headers[2].value).value
        community = sec_params_asn[0].value # technically the engine_id
      elsif [1, 2].include?(version)
        community = headers[1].value
      else
        logger.warn "unknown SNMP version #{version}"
        return
      end

      # Ensure the handler exists
      handler = @communities[community]
      if handler.nil?
        logger.warn "community or engine id not found #{community.inspect}"
        return
      end

      # Extract the PDU payload
      if version == 3
        security = @security[community]
        if security
          request_pdu, engine_id, engine_boots, engine_time = Message.decode(data, security_parameters: security)
        else
          logger.warn "no security defined for SNMPv3 messages to #{community.inspect}"
          return
        end
      else
        request_pdu = PDU.decode(data)
      end

      # Process the request
      case request_pdu.type
      when Inform
        logger.info "received an inform request"

        # Acknowledge the inform
        if request_pdu.version == 3
          engine_id = community
          context = ""
          pdu = ScopedPDU.build(:response,
            headers: [community, context],
            varbinds: request_pdu.varbinds.collect{|v| {oid: v.oid} },
            request_id: request_pdu.request_id
          )
          encoded_response = Message.encode(pdu, security_parameters: @security, engine_boots: @boots, engine_time: v3_time)
        else
          response_pdu = PDU.build(:response,
            headers: [request_pdu.version, request_pdu.community],
            varbinds: request_pdu.varbinds.collect{|v| {oid: v.oid} },
            request_id: request_pdu.request_id
          )
          encoded_response = response_pdu.to_der
        end

        send(ip, port, encoded_response)

        if handler.respond_to? :inform
          handler.inform(request_pdu, ip, port, self)
        end
      when V1_Trap, V2_Trap
        logger.info "received trap"
        # reference: https://github.com/hallidave/ruby-snmp/blob/320e2395c082c8f54f070ce3be05d96f1dbfb500/lib/snmp/pdu.rb#L354

        if handler.respond_to? :trap
          handler.trap(request_pdu, ip, port, self)
        end
      else
        custom_message_handler(handler, request_pdu, ip, port)
      end
    rescue => e
      logger.error "processing SNMP message\n#{e.message}\n#{e.backtrace.join("\n")}"
    end

    # Overwrite to with your transport
    #
    # @param [Object] ip the IP address (in the format you expect for the transport)
    # @param [Integer] port the port the remote client is communicating on
    # @param [String] data the raw response data
    #
    def send(ip, port, data)
      raise "SNMP agent send not implemented"
    end

    # Overrwite if you would like to handle additional message types
    #
    # @param [Object] handler the object handling the request
    # @param [NETSNMP::PDU] request_pdu the request object
    # @param [Object] ip the IP address (in the format you expect for the transport)
    # @param [Integer] port the port the remote client is communicating on
    #
    def custom_message_handler(handler, request_pdu, ip, port)
      logger.warn "ignoring unexpected SNMP request type #{request_pdu.type}"
    end
  end
end
