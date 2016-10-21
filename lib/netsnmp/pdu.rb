require 'forwardable'
module NETSNMP
  # Abstracts the PDU base structure into a ruby object. It gives access to its varbinds.
  #
  class PDU
    extend Forwardable 

    Error = Class.new(Error)
    class << self
      # factory method that abstracts initialization of the pdu types that the library supports.
      # 
      # @param [Symbol] type the type of pdu structure to build
      # @return [RequestPDU] a fully-formed request pdu
      # 
      def build(type, *args)
        case type
          when :get       then RequestPDU.new(Core::Constants::SNMP_MSG_GET, *args)
          when :getnext   then RequestPDU.new(Core::Constants::SNMP_MSG_GETNEXT, *args)
          when :getbulk   then RequestPDU.new(Core::Constants::SNMP_MSG_GETBULK, *args)
          when :set       then RequestPDU.new(Core::Constants::SNMP_MSG_SET, *args)
          when :response  then ResponsePDU.new(Core::Constants::SNMP_MSG_RESPONSE, *args)
          else raise Error, "#{type} is not supported as type"
        end
      end
    end

    attr_reader :options, :varbinds

    def_delegators :@options, :[]

    # @param [FFI::Pointer] the pointer to the initialized structure
    #
    def initialize(type, obj)
      @type = type
      @varbinds = []
      if obj.is_a?(Hash)
        @options = obj
      else
        @options = {}
        decode_ber(obj)
      end
    end


    def to_ber
      sequence = String.new 
      sequence << BER.encode(@options[:version])
      sequence << BER.encode(@options[:community])
      sequence << encode_payload
      BER.encode_sequence(sequence)
    end

    # Adds a request varbind to the pdu
    # 
    # @param [OID] oid a valid oid
    # @param [Hash] options additional request varbind options
    # @option options [Object] :value the value for the oid
    def add_varbind(oid, **options)
      @varbinds << RequestVarbind.new(oid, options)
    end
    alias_method :<<, :add_varbind

    private

    def type_ber_code(type: @type)
      typ = case type
      when Integer then type
      when :get then 0
      when :getnext then 1
      when :response then 2
      when :set then 3
      when :getbulk then 5
      else 
        raise Error, "#{type}: unsupported type"
      end
      0xa0 + type
    end

    def encode_payload

      code = type_ber_code
      payload_sequence = String.new

      payload_sequence << BER.encode(@options[:request_id])
      payload_sequence << BER.encode(0) # error
      payload_sequence << BER.encode(0) # error_index

      payload_sequence << BER.encode_sequence(@varbinds.map(&:to_ber).join)
       BER.encode_context(payload_sequence, code: 0)
    end


    def decode_ber(stream)

      str = StringIO.new(stream)
      #sequence
      sequence = BER.decode(str)
      options[:version] = sequence.next
      options[:community] = sequence.next
      pdu_type, requeststream = sequence.next 
      # validate if this pdu type is the same as the one set

      str = StringIO.new(requeststream)
      options[:request_id] = BER.decode(str)
      options[:error_status] = BER.decode(str)
      options[:error_index] = BER.decode(str)
   
      #sequence
      varsequence = BER.decode(str)
      varsequence.each do |varbind|
        oid, value = Array(varbind)
        add_varbind(oid, value: value) 
      end


    end
  end

  # Abstracts the request PDU
  # Main characteristic is that it has a write-only API, in that you can add varbinds to it.
  #
  class RequestPDU < PDU

  end

  # Abstracts the response PDU
  # Main characteristic is: it reads the values on initialization (because the response structure
  # is at some point free'd). It is therefore a read-only entity
  #
  class ResponsePDU < PDU


  end
end
