# frozen_string_literal: true
module NETSNMP
  # Abstracts the OID structure
  #
  class OID
    OIDREGEX = /^[\d\.]*$/

    attr_reader :code

    # @param [String] code the oid code 
    #
    def initialize(code)
      @code = code
    end

    def self.build(o)
      case o
      when OID then o
      when Array
        self.new(o.join('.'))
      when OIDREGEX
        o = o[1..-1] if o.start_with?('.')
        self.new(o)
      # TODO: MIB to OID
      else raise Error, "can't convert #{o} to OID"
      end
    end

    def to_ary
      @ary ||= begin
        ary = code.split('.')
        ary = ary[1..-1] if ary[0].empty?
        ary.map(&:to_i)
      end
    end

    def to_der
      to_asn.to_der
    end
    

    def to_asn
      OpenSSL::ASN1::ObjectId.new(@code)
    end

    def to_s ; code ; end

    def ==(other)
      case other
      when String then code == other
      else super
      end
    end
    # @param [OID, String] child oid another oid
    # @return [true, false] whether the given OID belongs to the sub-tree
    #
    def parent_of?(child_oid)
      child_code = child_oid.is_a?(OID) ? child_oid.code : child_oid
      child_code.match(%r/\A#{code}\./)
    end
  end
end
