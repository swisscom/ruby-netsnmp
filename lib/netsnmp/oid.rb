# frozen_string_literal: true

module NETSNMP
  # Abstracts the OID structure
  #
  module OID
    using StringExtensions

    OIDREGEX = /^[\d.]*$/.freeze

    module_function

    def build(id)
      oid = MIB.oid(id)

      raise Error, "no OID found for #{id}" unless oid

      oid = oid.delete_prefix(".") if oid.start_with?(".")
      oid
    end

    def to_asn(oid)
      OpenSSL::ASN1::ObjectId.new(oid)
    end

    # @param [OID, String] child oid another oid
    # @return [true, false] whether the given OID belongs to the sub-tree
    #
    def parent?(parent_oid, child_oid)
      child_oid.match?(/\A#{parent_oid}\./)
    end
  end
end
