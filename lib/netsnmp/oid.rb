module NETSNMP
  # Abstracts the OID structure
  #
  class OID
    Error = Class.new(Error)
    OIDREGEX = /^[\d\.]*$/

    class << self

      # @return [Integer] the default oid size in bytes
      def default_size
        @default_size ||= Core::Inline.oid_size
      end
  
      # @param [FFI::Pointer] pointer the pointer to the beginning ot the memory octet
      # @param [Integer] length the length of the oid
      # @return [String] the oid code (ex: "1.2.4.56.3.4.5"...)
      #
      def read_pointer(pointer, length)
        pointer.__send__(:"read_array_of_uint#{default_size * 8}", length).join('.')
      end
  
      # @see read_pointer
      # @return [OID] an OID object initialized from a code read from memory
      #
      def from_pointer(pointer, length)
        new(read_pointer(pointer, length))
      end

    end

    attr_reader :code

    # @param [String] code the oid code 
    #
    def initialize(code)
      @struct = FFI::MemoryPointer.new(OID::default_size * Core::Constants::MAX_OID_LEN)
      @length_pointer = FFI::MemoryPointer.new(:size_t)
      @length_pointer.write_int(Core::Constants::MAX_OID_LEN)
      existing_oid = case code
        when OIDREGEX then Core::LibSNMP.read_objid(code, @struct, @length_pointer)
        else Core::LibSNMP.get_node(code, @struct, @length_pointer)
      end
      raise Error, "unsupported oid: #{code}" if existing_oid.zero?
    end

    # @return [String] the oid code
    # 
    def code ; @code ||= OID.read_pointer(pointer, length) ; end 
    
    # @return [String] the pointer to the structure 
    # 
    def pointer ; @struct ; end

    # @return [Integer] length of the oid 
    #     
    def length ; @length_pointer.read_int ; end

    # @return [Integer] size of the oid 
    #     
    def size ; length * NETSNMP::OID.default_size ; end

    def to_s ; code ; end

    # @param [OID, String] child oid another oid
    # @return [true, false] whether the given OID belongs to the sub-tree
    #
    def parent_of?(child_oid)
      child_code = child_oid.is_a?(OID) ? child_oid.code : child_oid
      child_code.start_with?(code)
    end
  end

  # SNMP v3-relevant OIDs

  class MD5OID < OID
    def initialize ; super("1.3.6.1.6.3.10.1.1.2") ; end
  end
  class SHA1OID < OID
    def initialize ; super("1.3.6.1.6.3.10.1.1.3") ; end
  end
  class NoAuthOID < OID
    def initialize ; super("1.3.6.1.6.3.10.1.1.1") ; end
  end
  class AESOID < OID
    def initialize ; super("1.3.6.1.6.3.10.1.2.4") ; end
  end
  class DESOID < OID
    def initialize ; super("1.3.6.1.6.3.10.1.2.2") ; end
  end
  class NoPrivOID < OID
    def initialize ; super("1.3.6.1.6.3.10.1.2.1") ; end
  end 
end
