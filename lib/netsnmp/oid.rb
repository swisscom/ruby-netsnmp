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
  class AuthOID < OID
    def generate_key(session, user, pass)
      raise Error, "no given Authorization User" unless user
      raise Error, "no given Authorization Password" unless pass

      session[:securityAuthProto] = pointer
      session[:securityName] = FFI::MemoryPointer.from_string(user)
      session[:securityNameLen] = user.length

      auth_len_ptr = FFI::MemoryPointer.new(:size_t)
      auth_len_ptr.write_int(Core::Constants::USM_AUTH_KU_LEN)

      auth_key_result = Core::LibSNMP.generate_Ku(pointer,
                                 session[:securityAuthProtoLen],
                                 pass,
                                 pass.length,
                                 session[:securityAuthKey],
                                 auth_len_ptr)
      unless auth_key_result == Core::Constants::SNMPERR_SUCCESS
        raise AuthenticationFailed, "failed to authenticate #{auth_user} in #{@host}"
      end
      session[:securityAuthKeyLen] = auth_len_ptr.read_int
    end
  end

  class PrivOID < OID

    def generate_key(session, user, pass)
      raise Error, "no given Priv User" unless user
      raise Error, "no given Priv Password" unless pass

      session[:securityPrivProto] = pointer

      # other necessary lengths
      priv_len_ptr = FFI::MemoryPointer.new(:size_t)
      priv_len_ptr.write_int(Core::Constants::USM_PRIV_KU_LEN)

      # NOTE I know this is handing off the AuthProto, but generates a proper
      # key for encryption, and using PrivProto does not.
      priv_key_result = Core::LibSNMP.generate_Ku(session[:securityAuthProto],
                                                  session[:securityAuthProtoLen],
                                                  pass,
                                                  pass.length,
                                                  session[:securityPrivKey],
                                                  priv_len_ptr)

      unless priv_key_result == Core::Constants::SNMPERR_SUCCESS
        raise AuthenticationFailed, "failed to authenticate #{auth_user} in #{@host}"
      end
      session[:securityPrivKeyLen] = priv_len_ptr.read_int

    end
  end

  class MD5OID < AuthOID
    def initialize ; super("1.3.6.1.6.3.10.1.1.2") ; end
  end
  class SHA1OID < AuthOID
    def initialize ; super("1.3.6.1.6.3.10.1.1.3") ; end
  end
  class NoAuthOID < AuthOID
    def initialize ; super("1.3.6.1.6.3.10.1.1.1") ; end
    def generate_key(session, *) 
      session[:securityAuthProto] = pointer
    end
  end
  class AESOID < PrivOID
    def initialize ; super("1.3.6.1.6.3.10.1.2.4") ; end
  end
  class DESOID < PrivOID
    def initialize ; super("1.3.6.1.6.3.10.1.2.2") ; end
  end
  class NoPrivOID < PrivOID
    def initialize ; super("1.3.6.1.6.3.10.1.2.1") ; end
    def generate_key(session, *) 
      session[:securityPrivProto] = pointer
    end
  end 
end
