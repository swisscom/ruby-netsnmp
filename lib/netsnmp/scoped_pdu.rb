# frozen_string_literal: true

module NETSNMP
  class ScopedPDU < PDU
    using ASNExtensions

    attr_reader :engine_id

    attr_accessor :security_level, :auth_param

    def initialize(type:, headers:, **options)
      @engine_id, @context = headers
      super(type: type, headers: [3, nil], **options)
    end

    private

    def encode_headers_asn
      [
        OpenSSL::ASN1::OctetString.new(@engine_id || "").with_label(:engine_id),
        OpenSSL::ASN1::OctetString.new(@context || "").with_label(:context)
      ]
    end
  end
end
