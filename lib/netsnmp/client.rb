# frozen_string_literal: true
module NETSNMP
  # Main Entity, provides the user-facing API to communicate with SNMP Agents
  #
  # Under the hood it creates a "session" (analogous to the net-snmp C session), which will be used
  # to proxy all the communication to the agent. the Client ensures that you only write pure ruby and
  # read pure ruby, not concerning with snmp-speak like PDUs, varbinds and the like. 
  #
  #
  class Client
    
    # @param [String] hostname the hostname of the agent
    # @param [Hash] options the set of options to open the session.
    #
    # @see Session#initialize
    def initialize(options)
      version = options[:version]
      version = case version 
        when Integer then version # assume the use know what he's doing
        when /v?1/ then 0 
        when /v?2c?/ then 1 
        when /v?3/, nil then 3
      end

      @session ||= version == 3 ? V3Session.new(options) : Session.new(options)
      if block_given?
        begin
          yield self
        ensure
          close
        end
      end
    end

    # @see Session#close
    def close
      @session.close
    end

    # Performs an SNMP GET Request
    # 
    # @param [String] oid the oid to get
    # @param [Hash] options the varbind options (see Varbind)
    # @option options [true, false] :response if true, the method returns a PDU
    #
    # @return [String] the value for the oid
    #
    def get(*oids)
      request = @session.build_pdu(:get, *oids)
      response = @session.send(request)
      yield response if block_given?
      response.varbinds.first.value
    end

    # Performs an SNMP GETNEXT Request
    # 
    # @param [String] oid the oid to get
    # @param [Hash] options the varbind options (see Varbind)
    # @option options [true, false] :response if true, the method returns a PDU
    #
    # @return [String] the value for the next oid
    # 
    # @note this method is used as a sub-routine for the walk
    #
    def get_next(*oids)
      request = @session.build_pdu(:getnext, *oids)
      response = @session.send(request)
      yield response if block_given?
      varbind = response.varbinds.first
      [varbind.oid.code, varbind.value]
    end

    # Perform a SNMP Walk (issues multiple subsequent GENEXT requests within the subtree rooted on an OID)
    #
    # @param [String] oid the root oid from the subtree
    # @param [Hash] options the varbind options 
    #
    # @return [Enumerator] the enumerator-collection of the oid-value pairs
    #
    def walk(oid)
      walkoid = OID.build(oid)
      Enumerator.new do |y|
        code = walkoid
        first_response_code = nil
        catch(:walk) do
          loop do
            get_next(oid: code) do |response|
              response.varbinds.each do |varbind|
                code = varbind.oid_code
                if !walkoid.parent_of?(code) or 
                    varbind.value.eql?(:endofmibview) or
                    code == first_response_code
                  throw(:walk)             
                else
                  y << [code, varbind.value]
                end
                first_response_code ||= code
              end
            end
          end
        end
      end
    end

    # Perform a SNMP GETBULK Request (performs multiple GETNEXT)
    #
    # @param [String] oid the first oid
    # @param [Hash] options the varbind options 
    # @option options [Integer] :errstat sets the number of objects expected for the getnext instance
    # @option options [Integer] :errindex number of objects repeating for all the repeating IODs. 
    #
    # @return [Enumerator] the enumerator-collection of the oid-value pairs
    #
    #def get_bulk(oid)
    #  request = @session.build_pdu(:getbulk, *oids)
    #  request[:error_status]  = options.delete(:non_repeaters) || 0
    #  request[:error_index] = options.delete(:max_repetitions) || 10
    #  response = @session.send(request)
    #  Enumerator.new do |y|
    #    response.varbinds.each do |varbind|
    #      y << [ varbind.oid_code, varbind.value ]
    #    end
    #  end
    #end

    # Perform a SNMP SET Request
    #
    # @param [String] oid the oid to update
    # @param [Hash] options the varbind options 
    # @option options [Object] :value value to update the oid with. 
    #
    def set(*oids)
      request = @session.build_pdu(:set, *oids)
      response = @session.send(request)
      yield response if block_given? 
      response.varbinds.map(&:value)
    end
  end
end
