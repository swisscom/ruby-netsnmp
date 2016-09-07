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
    # @param [OID, String] oid_code the oid to get
    # @param [Hash] options the varbind options (see Varbind)
    # @option options [true, false] :response_pdu if true, the method returns a PDU
    #
    # @return [String] the value for the oid
    #
    def get(oid_code, **options)
      request_pdu = RequestPDU.build(:get)
      oid = oid_code.is_a?(OID) ? oid_code : OID.new(oid_code)
      request_pdu.add_varbind(oid, options)
      yield request_pdu if block_given? 
      response_pdu = @session.send(request_pdu)
      case options[:response_type] 
        when :pdu then response_pdu
        else response_pdu.value
      end
    end

    # Performs an SNMP GETNEXT Request
    # 
    # @param [OID, String] oid_code the oid to get
    # @param [Hash] options the varbind options (see Varbind)
    # @option options [true, false] :response_pdu if true, the method returns a PDU
    #
    # @return [String] the value for the next oid
    # 
    # @note this method is used as a sub-routine for the walk
    #
    def get_next(oid_code, **options)
      request_pdu = RequestPDU.build(:getnext)
      oid = oid_code.is_a?(OID) ? oid_code : OID.new(oid_code)
      request_pdu.add_varbind(oid, options)
      yield request_pdu if block_given? 
      response_pdu = @session.send(request_pdu)
      case options[:response_type] 
        when :pdu then response_pdu
        else response_pdu.value
      end
    end

    # Perform a SNMP Walk (issues multiple subsequent GENEXT requests within the subtree rooted on an OID)
    #
    # @param [OID, String] oid_code the root oid from the subtree
    # @param [Hash] options the varbind options 
    #
    # @return [Enumerator] the enumerator-collection of the oid-value pairs
    #
    def walk(oid_code, **options)
      options[:response_type] = :pdu
      walkoid = oid_code.is_a?(OID) ? oid_code : OID.new(oid_code)
      Enumerator.new do |y|
        code = walkoid.code
        first_response_code = nil
        catch(:walk) do
          loop do
            response_pdu = get_next(code, options)
            response_pdu.varbinds.each do |varbind|
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
    # @param [OID, String] oid_code the first oid
    # @param [Hash] options the varbind options 
    # @option options [Integer] :errstat sets the number of objects expected for the getnext instance
    # @option options [Integer] :errindex number of objects repeating for all the repeating IODs. 
    #
    # @return [Enumerator] the enumerator-collection of the oid-value pairs
    #
    def get_bulk(oid_code, **options)
      request_pdu = RequestPDU.build(:getbulk)
      request_pdu[:errstat]  = options.delete(:non_repeaters) || 0
      request_pdu[:errindex] = options.delete(:max_repetitions) || 10
      request_pdu.add_varbind(OID.new(oid_code), options)
      yield request_pdu if block_given? 
      response_pdu = @session.send(request_pdu)
      Enumerator.new do |y|
        response_pdu.varbinds.each do |varbind|
          y << [ varbind.oid_code, varbind.value ]
        end
      end
    end

    # Perform a SNMP SET Request
    #
    # @param [OID, String] oid_code the oid to update
    # @param [Hash] options the varbind options 
    # @option options [Object] :value value to update the oid with. 
    #
    def set(oid_code, **options)
      request_pdu = PDU.build(:set)
      request_pdu.add_varbind(OID.new(oid_code), options)
      yield request_pdu if block_given? 
      response_pdu = @session.send(request_pdu)
      response_pdu.value
    end
  end
end
