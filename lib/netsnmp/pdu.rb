require 'forwardable'
module NETSNMP
  # Abstracts the PDU base structure into a ruby object. It gives access to its varbinds.
  #
  class PDU
    @request_id_counter = 0
    @counter_monitor = Mutex.new
    MAXREQUESTS = 1024
    def self.generate_request_id
      @counter_monitor.synchronize do
        current = @request_id_counter   
        @request_id_counter = current >= MAXREQUESTS ? 0 : current + 1
        current
      end
    end

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
          when :get       then new(0, *args)
          when :getnext   then new(1, *args)
          when :getbulk   then new(5, *args)
          when :set       then new(3, *args)
          when :response  then new(2, *args)
          else raise Error, "#{type} is not supported as type"
        end
      end
    end

    attr_reader :options, :varbinds

    def_delegators :@options, :[], :[]=

    # @param [FFI::Pointer] the pointer to the initialized structure
    #
    def initialize(type, obj)
      @type = type
      @varbinds = []
      if obj.is_a?(Hash)
        @options = obj
        @options[:request_id] ||= PDU.generate_request_id
      else
        @options = {}
        decode_ber(obj)
      end
    end



    def to_der
      to_asn.to_der
    end

    # Adds a request varbind to the pdu
    # 
    # @param [OID] oid a valid oid
    # @param [Hash] options additional request varbind options
    # @option options [Object] :value the value for the oid
    def add_varbind(oid, **options)
      @varbinds << Varbind.new(oid, options)
    end
    alias_method :<<, :add_varbind

    private

    def to_asn
      version_asn = OpenSSL::ASN1::Integer.new( @options[:version] )
      community_asn = OpenSSL::ASN1::OctetString.new( @options[:community] )
    
      request_id_asn = OpenSSL::ASN1::Integer.new( @options[:request_id] )
      error_asn = OpenSSL::ASN1::Integer.new( @options[:error_status] || 0 )
      error_index_asn = OpenSSL::ASN1::Integer.new( @options[:error_index] || 0 )

      varbind_asns = OpenSSL::ASN1::Sequence.new( @varbinds.map(&:to_asn) )

      request_asn = OpenSSL::ASN1::ASN1Data.new( [request_id_asn,
                                                  error_asn, error_index_asn,
                                                  varbind_asns], @type,
                                                  :CONTEXT_SPECIFIC )

      OpenSSL::ASN1::Sequence.new( [ version_asn, community_asn, request_asn ] )
    end

    def decode_ber(stream)
      asn_tree = OpenSSL::ASN1.decode(stream)
      *headers, request = asn_tree.value

      options[:version] = headers[0].value.to_i
      options[:community] = headers[1].value

      @type = request.tag

      *request_headers, varbinds = request.value

      options[:request_id] = request_headers[0].value.to_i
      options[:error_status] = request_headers[1].value.to_i
      options[:error_index] = request_headers[2].value.to_i
 
      varbinds.value.each do |varbind|
        oid_asn, val_asn  = varbind.value
        oid = oid_asn.value
        add_varbind(oid, value: val_asn) 
      end
    end
  end
end
