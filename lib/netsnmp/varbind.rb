module NETSNMP
  # Abstracts the PDU variable structure into a ruby object
  #
  class Varbind
    Error = Class.new(Error)

    attr_reader :struct

    # @param [FFI::Pointer] pointer to the variable list
    def initialize(pointer)
      @struct = Core::Structures::VariableList.new(pointer)
    end


    def to_ber
      encoded = String.new
      encoded << @oid.to_ber
      encoded << BER.encode(@value)
      BER.encode_sequence(encoded)
    end
  end


  # Abstracts the Varbind used for the PDU Request
  class RequestVarbind < Varbind

    # @param [RequestPDU] pdu the request pdu for this varbind
    # @param [OID] oid the oid for this varbind
    # @param [Object] value the value for the oid
    # @param [Hash] options additional options
    # @option options [Symbol, Integer, nil] :type C net-snmp type flag,  
    #   type-label for value (see #convert_type), if not set it's inferred from the value
    #
    def initialize(pdu, oid, value, options={})
      @oid = OID.new(oid)
      @value = value
      type = case options[:type]
        when Integer then options[:type] # assume that the code is properly passed
        when Symbol  then convert_type(options[:type]) # DSL-specific API
        when nil     then infer_from_value(value)
        else 
          raise Error, "#{options[:type]} is an unsupported type"
      end

      value_length = case type
        when Core::Constants::ASN_NULL,
             Core::Constants::SNMP_NOSUCHOBJECT,
             Core::Constants::SNMP_NOSUCHINSTANCE,
             Core::Constants::SNMP_ENDOFMIBVIEW
          0
        else value ? value.size : 0 
      end
      value = convert_value(value, type)

#      pointer = Core::LibSNMP.snmp_pdu_add_variable(pdu.pointer, oid.pointer, oid.length, type, value, value_length) 
#      super(pointer)
    end


    private

    # @param [Object] value value to infer the type from
    # @return [Integer] the C net-snmp flag indicating the type
    # @raise [Error] when the value is from an unexpected type
    #
    def infer_from_value(value)
      case value
        when String then Core::Constants::ASN_OCTET_STR
        when Fixnum then Core::Constants::ASN_INTEGER
        when OID then Core::Constants::ASN_OBJECT_ID
        when nil then Core::Constants::ASN_NULL
        else raise Error, "#{value} is from an unsupported type"
      end
    end

    # @param [Symbol] symbol_type symbol representing the type
    # @return [Integer] the C net-snmp flag indicating the type
    # @raise [Error] when the symbol is unsupported
    #
    def convert_type(symbol_type)
      case symbol_type
        when :integer    then Core::Constants::ASN_INTEGER
        when :gauge      then Core::Constants::ASN_GAUGE
        when :counter    then Core::Constants::ASN_COUNTER
        when :timeticks  then Core::Constants::ASN_TIMETICKS
        when :unsigned   then Core::Constants::ASN_UNSIGNED
        when :boolean    then Core::Constants::ASN_BOOLEAN
        when :string     then Core::Constants::ASN_OCTET_STR
        when :binary     then Core::Constants::ASN_BIT_STR
        when :ip_address then Core::Constants::ASN_IPADDRESS
        else 
          raise Error, "#{symbol_type} cannot be converted"
      end
    end

    # @param [Object] value the value to convert
    # @param [Integer] type the C net-snmp level object type flakg
    #
    # @return [FFI::Pointer] pointer to the memory location where the value is stored
    #
    def convert_value(value, type)
      case type
        when Core::Constants::ASN_INTEGER,
             Core::Constants::ASN_GAUGE,
             Core::Constants::ASN_COUNTER,
             Core::Constants::ASN_TIMETICKS,
             Core::Constants::ASN_UNSIGNED
          new_val = FFI::MemoryPointer.new(:long)
          new_val.write_long(value)
          new_val
        when Core::Constants::ASN_OCTET_STR,
             Core::Constants::ASN_BIT_STR,
             Core::Constants::ASN_OPAQUE
          value
        when Core::Constants::ASN_IPADDRESS
            # TODO
        when Core::Constants::ASN_OBJECT_ID
          value.pointer
        when Core::Constants::ASN_NULL,
             Core::Constants::SNMP_NOSUCHOBJECT,
             Core::Constants::SNMP_NOSUCHINSTANCE,
             Core::Constants::SNMP_ENDOFMIBVIEW
            nil
        else
          raise Error, "Unknown variable type: #{type}" 
      end
    end
  end

  # Abstracts the Varbind used for the PDU Response
  # 
  class ResponseVarbind < Varbind

    attr_reader :value, :oid_code

    # @param [FFI::Pointer] pointer pointer to the response varbind structure
    # 
    # @note it loads the value and oid code on initialization
    #
    def initialize(pointer)
      super
      @value    = load_varbind_value
      @oid_code = load_oid_code
    end

    private

    # @return [String] the oid code from the varbind
    def load_oid_code
      OID.read_pointer(@struct[:name], @struct[:name_length])
    end

    # @return [Object] the value for the varbind (a ruby type, a string, an integer, a symbol etc...)
    #
    def load_varbind_value
      object_type = @struct[:type]
      case object_type
      when Core::Constants::ASN_OCTET_STR, 
           Core::Constants::ASN_OPAQUE
        @struct[:val][:string].read_string(@struct[:val_len])
      when Core::Constants::ASN_INTEGER
        @struct[:val][:integer].read_long
      when Core::Constants::ASN_UINTEGER, 
           Core::Constants::ASN_TIMETICKS,  
           Core::Constants::ASN_COUNTER, 
           Core::Constants::ASN_GAUGE
        @struct[:val][:integer].read_ulong
      when Core::Constants::ASN_IPADDRESS
        @struct[:val][:objid].read_string(@struct[:val_len]).unpack('CCCC').join(".")
      when Core::Constants::ASN_NULL
        nil
      when Core::Constants::ASN_OBJECT_ID
        OID.from_pointer(@struct[:val][:objid], @struct[:val_len] / OID.default_size)
      when Core::Constants::ASN_COUNTER64
        counter = Core::Structures::Counter64.new(@struct[:val][:counter64])
        counter[:high] * 2^32 + counter[:low]
      when Core::Constants::ASN_BIT_STR
        # XXX not sure what to do here.  Is this obsolete?
      when Core::Constants::SNMP_ENDOFMIBVIEW
        :endofmibview
      when Core::Constants::SNMP_NOSUCHOBJECT
        :nosuchobject
      when Core::Constants::SNMP_NOSUCHINSTANCE
        :nosuchinstance
      else
        raise Error, "#{object_type} is an invalid type"
      end
    end

  end
end
