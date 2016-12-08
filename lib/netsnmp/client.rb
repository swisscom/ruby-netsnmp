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
    def initialize(hostname, options)
      @session ||= Session.new(hostname, options)
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
    def get(oid, **options)
      request = @session.build_pdu(:get)
      request.add_varbind(oid, value: options[:value])
      response = @session.send(request)
      case options[:response_type] 
        when :pdu then response
        else response.varbinds.first.value
      end
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
    def get_next(oid, **options)
      request = @session.build_pdu(:getnext)
      request.add_varbind(oid, value: options[:value])
      response = @session.send(request)
      case options[:response_type] 
        when :pdu then response
        else response.varbinds.first.value
      end
    end

    # Perform a SNMP Walk (issues multiple subsequent GENEXT requests within the subtree rooted on an OID)
    #
    # @param [String] oid the root oid from the subtree
    # @param [Hash] options the varbind options 
    #
    # @return [Enumerator] the enumerator-collection of the oid-value pairs
    #
    def walk(oid, **options)
      options[:response_type] = :pdu
      walkoid = OID.build(oid)
      Enumerator.new do |y|
        code = walkoid
        first_response_code = nil
        catch(:walk) do
          loop do
            response = get_next(code, options)
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

    # Perform a SNMP GETBULK Request (performs multiple GETNEXT)
    #
    # @param [String] oid the first oid
    # @param [Hash] options the varbind options 
    # @option options [Integer] :errstat sets the number of objects expected for the getnext instance
    # @option options [Integer] :errindex number of objects repeating for all the repeating IODs. 
    #
    # @return [Enumerator] the enumerator-collection of the oid-value pairs
    #
    def get_bulk(oid, **options)
      request = @session.build_pdu(:getbulk)
      request[:error_status]  = options.delete(:non_repeaters) || 0
      request[:error_index] = options.delete(:max_repetitions) || 10
      request.add_varbind(oid, value: options[:value])
      response = @session.send(request)
      Enumerator.new do |y|
        response.varbinds.each do |varbind|
          y << [ varbind.oid_code, varbind.value ]
        end
      end
    end

    # Perform a SNMP SET Request
    #
    # @param [String] oid the oid to update
    # @param [Hash] options the varbind options 
    # @option options [Object] :value value to update the oid with. 
    #
    def set(oid, **options)
      request = @session.build_pdu(:set)
      request.add_varbind(oid, **options)
      yield request if block_given? 
      response = @session.send(request)
      response.varbinds.map(&:value)
    end
  end
end
