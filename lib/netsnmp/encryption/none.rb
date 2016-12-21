# frozen_string_literal: true
module NETSNMP
  module Encryption
    class None

      def initialize(*)
      end

      def encrypt(pdu)
        pdu.send(:to_asn)
      end
      def decrypt(stream, *)
        stream
      end
    end
  end
end
