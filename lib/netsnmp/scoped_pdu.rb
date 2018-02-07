# frozen_string_literal: true

module NETSNMP
  class ScopedPDU < PDU
    attr_reader :engine_id

    def initialize(type:, headers:, **options)
      @engine_id, @context = headers
      super(type: type, headers: [3, nil], **options)
    end

    def encode_headers_asn
      [OpenSSL::ASN1::OctetString.new(@engine_id || ""),
       OpenSSL::ASN1::OctetString.new(@context || "")]
    end
  end
end
