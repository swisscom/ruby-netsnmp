module NETSNMP::Core
  # Maps to the relevant netsnmp C library structs. 
  module Structures
    extend FFI::Library
    typedef :u_long, :oid

    callback(:snmp_callback, [ :int, :pointer, :int, :pointer, :pointer ], :int)
    callback(:netsnmp_callback, [ :int, :pointer, :int, :pointer, :pointer ], :int)

    class SessionList < FFI::Struct
      layout(
        :next, :pointer,
        :session, :pointer,
        :transport, :pointer,
        :internal, :pointer
      )
    end

    class Transport < FFI::Struct
      layout(
        :domain, :pointer,
        :domain_length, :int,
        :local, :pointer,
        :local_length, :int,
        :remote, :pointer,
        :remote_length, :int,
        :sock, :int,
        :flags, :u_int, 
        :data, :pointer,
        :data_length, :int,
        :msgMaxSize, :size_t,
        :base_transport, :pointer
      )
    end

    class Session < FFI::Struct
      layout(
        :version, :long,
        :retries, :int,
        :timeout, :long,
        :flags, :u_long,
        :subsession, :pointer,
        :next, :pointer,
        :peername, :pointer,
        :remote_port, :u_short,
        :localname, :pointer,
        :local_port, :u_short,
        :authenticator, callback([ :pointer, :pointer, :pointer, :uint ], :pointer),
        :callback, :netsnmp_callback,
        :callback_magic, :pointer,
        :s_errno, :int,
        :s_snmp_errno, :int,
        :sessid, :long,
        :community, :pointer,
        :community_len, :size_t,
        :rcvMsgMaxSize, :size_t,
        :sndMsgMaxSize, :size_t,
        :isAuthoritative, :u_char,
        :contextEngineID, :pointer,
        :contextEngineIDLen, :size_t,
        :engineBoots, :u_int,
        :engineTime, :u_int,
        :contextName, :pointer,
        :contextNameLen, :size_t,
        :securityEngineID, :pointer,
        :securityEngineIDLen, :size_t,
        :securityName, :pointer,
        :securityNameLen, :size_t,
        :securityAuthProto, :pointer,
        :securityAuthProtoLen, :size_t,
        :securityAuthKey, [:u_char, 32],
        :securityAuthKeyLen, :size_t,
        :securityAuthLocalKey, :pointer,
        :securityAuthLocalKeyLen, :size_t,
        :securityPrivProto, :pointer,
        :securityPrivProtoLen, :size_t,
        :securityPrivKey, [:u_char, 32],
        :securityPrivKeyLen, :size_t,
        :securityPrivLocalKey, :pointer,
        :securityPrivLocalKeyLen, :size_t,
        :securityModel, :int,
        :securityLevel, :int,
        :paramName, :pointer,
        :securityInfo, :pointer,
        :myvoid, :pointer
      )
    end

    class Vardata < FFI::Union
      layout(
        :integer, :pointer,
        :string, :pointer,
        :objid, :pointer,
        :bitstring, :pointer,
        :counter64, :pointer,
        :float, :pointer,
        :double, :pointer
      )
    end

    class VariableList < FFI::Struct
      layout(
        :next_variable, :pointer,#VariableList.typed_pointer,
        :name, :pointer,
        :name_length, :size_t,
        :type, :u_char,
        :val, Vardata,
        :val_len, :size_t,
        :name_loc, [:oid, Constants::MAX_OID_LEN],
        :buf, [:u_char, 40],
        :data, :pointer,
        :dataFreeHook, callback([ :pointer ], :void),
        :index, :int
      )
    end


    class PDU < FFI::Struct
      layout(
         :version, :long,
         :command, :int,
         :reqid, :long,
         :msgid, :long,
         :transid, :long,
         :sessid, :long,
         :errstat, :long,
         :errindex, :long,
         :time, :u_long,
         :flags, :u_long,
         :securityModel, :int,
         :securityLevel, :int,
         :msgParseModel, :int,
         :transport_data, :pointer,
         :transport_data_length, :int,
         :tDomain, :pointer,
         :tDomainLen, :size_t,
         :variables, :pointer,
         :community, :pointer,
         :community_len, :size_t,
         :enterprise, :pointer,
         :enterprise_length, :size_t,
         :trap_type, :long,
         :specific_type, :long,
         :agent_addr, [:uchar, 4],
         :contextEngineID, :pointer,
         :contextEngineIDLen, :size_t,
         :contextName, :pointer,
         :contextNameLen, :size_t,
         :securityEngineID, :pointer,
         :securityEngineIDLen, :size_t,
         :securityName, :pointer,
         :securityNameLen, :size_t,
         :priority, :int,
         :range_subid, :int,
         :securityStateRef, :pointer
      )
    end

    class Counter64 < FFI::Struct
      layout(
        :high, :u_long,
        :low, :u_long
      )
    end

  end
end
