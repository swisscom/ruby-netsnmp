require 'forwardable'
module NETSNMP
  # Abstracts the PDU base structure into a ruby object. It gives access to its varbinds.
  #
  class PDU
    # TODO: make this random!
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
      def build(type, **options)
        options[:type] = case type
          when :get       then 0
          when :getnext   then 1
          when :getbulk   then 5
          when :set       then 3
          when :response  then 2
          else raise Error, "#{type} is not supported as type"
        end
        new(options)
      end
    end

    attr_reader :options, :varbinds, :type

    def_delegators :@options, :[], :[]=

    # @param [FFI::Pointer] the pointer to the initialized structure
    #
    def initialize(options={})
      @type = options.delete(:type)
      @options = options
      @varbinds = []
      @options[:request_id] ||= PDU.generate_request_id
    end

    # helper method; to keep using the same failed response for v3,
    # one passes the original request pdu and sets what needs to be set
    def from_pdu(pdu)
      @options[:engine_id] = pdu.options[:engine_id]
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

    def decode(der)
      asn_tree = case der
      when String
        OpenSSL::ASN1.decode(der)
      when OpenSSL::ASN1::ASN1Data
        der
      else
        raise "#{der}: unexpected data"
      end

      *headers, request = asn_tree.value

      decode_headers_asn(*headers)

      @type = request.tag

      *request_headers, varbinds = request.value

      @options[:request_id] = request_headers[0].value.to_i
      @options[:error_status] = request_headers[1].value.to_i
      @options[:error_index] = request_headers[2].value.to_i
 
      varbinds.value.each do |varbind|
        oid_asn, val_asn  = varbind.value
        oid = oid_asn.value
        add_varbind(oid, value: val_asn) 
      end
    end

    def to_asn
      request_id_asn = OpenSSL::ASN1::Integer.new( @options[:request_id] )
      error_asn = OpenSSL::ASN1::Integer.new( @options[:error_status] || 0 )
      error_index_asn = OpenSSL::ASN1::Integer.new( @options[:error_index] || 0 )

      varbind_asns = OpenSSL::ASN1::Sequence.new( @varbinds.map(&:to_asn) )

      request_asn = OpenSSL::ASN1::ASN1Data.new( [request_id_asn,
                                                  error_asn, error_index_asn,
                                                  varbind_asns], @type,
                                                  :CONTEXT_SPECIFIC )

      OpenSSL::ASN1::Sequence.new( [ *encode_headers_asn, request_asn ] )
    end

    private

    def encode_headers_asn
      if options[:version] == 3 || @options[:engine_id]
        [ OpenSSL::ASN1::OctetString.new(@options[:engine_id] || ""),
          OpenSSL::ASN1::OctetString.new(@options[:context] || "") ] 
      else
        [ OpenSSL::ASN1::Integer.new( @options[:version] ),
          OpenSSL::ASN1::OctetString.new( @options[:community] ) ]
      end
    end

    def decode_headers_asn(asn1, asn2)
      # if first one is integer, this is a raw SNMP PDU
      # if not, it was integrated in the SNMP v3 message,
      # and first part is the engine
      case asn1
      when OpenSSL::ASN1::OctetString
        @options[:engine_id] = asn1.value
        @options[:context] = asn2.value
      when OpenSSL::ASN1::Integer
        @options[:version] = asn1.value.to_i
        @options[:community] = asn2.value
      end
    end
  end
end
