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

  end
end
