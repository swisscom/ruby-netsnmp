module NETSNMP
  # Abstracts the OID structure
  #
  class OID
    Error = Class.new(Error)
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
        self.new(".#{o.join('.')}")
      when OIDREGEX
        self.new(o)
      # TODO: MIB to OID
      else raise Error, "#{o}: can't convert to OID"
      end
    end

    def to_ary
      @ary ||= begin
        ary = code.split('.')
        ary = ary[1..-1] if ary[0].empty?
        ary.map(&:to_i)
      end
    end

    def to_ber
      fst, scd, *rest = to_ary
      raise Error, "Invalid OID" unless (0..2).include?(fst)
      beg = fst * 40 + scd
      rest.unshift(beg)
      encoded = rest.pack("w*")
      encoded.prepend([6, encoded.length].pack("CC"))
      encoded
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
