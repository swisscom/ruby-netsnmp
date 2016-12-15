module NETSNMP
  class ScopedPDU < PDU


    attr_reader :engine_id

    def initialize(type: , headers:,
                           request_id: nil,
                           error_status: 0,
                           error_index: 0,
                           varbinds: [])
      @engine_id, @context = headers
      super(type: type, headers: [3, nil], request_id: request_id, varbinds: varbinds)
    end

    def encode_headers_asn
      [ OpenSSL::ASN1::OctetString.new(@engine_id || ""),
        OpenSSL::ASN1::OctetString.new(@context   || "") ] 
    end 

    # helper method; to keep using the same failed response for v3,
    # one passes the original request pdu and sets what needs to be set
    def from_pdu(pdu)
      @engine_id = pdu.engine_id
    end
  end
end
