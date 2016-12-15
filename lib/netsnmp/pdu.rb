require 'forwardable'
module NETSNMP
  # Abstracts the PDU base structure into a ruby object. It gives access to its varbinds.
  #
  class PDU
    Error = Class.new(Error)


    # TODO: make this random!
    @request_id_counter = 0
    @counter_monitor = Mutex.new
    MAXREQUESTS = 1024
    class << self
      def generate_request_id
        @counter_monitor.synchronize do
          current = @request_id_counter   
          @request_id_counter = current >= MAXREQUESTS ? 0 : current + 1
          current
        end
      end

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

        version, community = headers.map(&:value)

        type = request.tag

        *request_headers, varbinds = request.value

        request_id = request_headers[0].value.to_i
        error_status = request_headers[1].value.to_i
        error_index  = request_headers[2].value.to_i
        # TODO: fail fast if errors here
    
        varbs = varbinds.value.map do |varbind|
          oid_asn, val_asn  = varbind.value
          oid = oid_asn.value
          { oid: oid, value: val_asn }
        end

        new(type: type, headers: [version, community],
                        error_status: error_status,
                        error_index: error_index,
                        request_id: request_id, 
                        varbinds: varbs)
      end

      # factory method that abstracts initialization of the pdu types that the library supports.
      # 
      # @param [Symbol] type the type of pdu structure to build
      # 
      def build(type, **args)
        typ = case type
          when :get       then 0
          when :getnext   then 1
#          when :getbulk   then 5
          when :set       then 3
          when :response  then 2
          else raise Error, "#{type} is not supported as type"
        end
        new(args.merge(type: typ))
      end
    end

    attr_reader :varbinds, :type

    attr_reader :version, :community, :request_id

    def initialize(type: , headers: , 
                           request_id: nil, 
                           error_status: 0,
                           error_index: 0,
                           varbinds: [])
      @version, @community = headers
      @version = @version.to_i
      @error_status = error_status
      @error_index  = error_index
      @type = type
      @varbinds = []
      varbinds.each do |varbind|
        add_varbind(varbind)
      end
      @request_id = request_id || PDU.generate_request_id
    end


    def to_der
      to_asn.to_der
    end

    # Adds a request varbind to the pdu
    # 
    # @param [OID] oid a valid oid
    # @param [Hash] options additional request varbind options
    # @option options [Object] :value the value for the oid
    def add_varbind(oid: , **options)
      @varbinds << Varbind.new(oid, **options)
    end
    alias_method :<<, :add_varbind


    def to_asn
      request_id_asn = OpenSSL::ASN1::Integer.new( @request_id )
      error_asn = OpenSSL::ASN1::Integer.new( @error_status )
      error_index_asn = OpenSSL::ASN1::Integer.new( @error_index )

      varbind_asns = OpenSSL::ASN1::Sequence.new( @varbinds.map(&:to_asn) )

      request_asn = OpenSSL::ASN1::ASN1Data.new( [request_id_asn,
                                                  error_asn, error_index_asn,
                                                  varbind_asns], @type,
                                                  :CONTEXT_SPECIFIC )

      OpenSSL::ASN1::Sequence.new( [ *encode_headers_asn, request_asn ] )
    end

    private

    def encode_headers_asn
      [ OpenSSL::ASN1::Integer.new( @version ),
        OpenSSL::ASN1::OctetString.new( @community ) ]
    end

  end
end
