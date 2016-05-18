module NETSNMP::Core
  module LibSNMP
    extend FFI::Library
    ffi_lib ["libnetsnmp", "netsnmp", "snmp"]
  
    callback(:snmp_callback, [ :int, :pointer, :int, :pointer, :pointer ], :int)
    callback(:netsnmp_callback, [ :int, :pointer, :int, :pointer, :pointer ], :int)
  
    # checks whether the oid is supported
    attach_function :read_objid, [:string, :pointer, :pointer], :int, blocking: true
    # checks whether the mib is supported
    attach_function :get_node, [:string, :pointer, :pointer], :int, blocking: true
  
    # initializes internal stuff, loads mibs, etc etc etc...
    attach_function :init_snmp, [ :string ], :void, blocking: true
  
    # PDU API
    attach_function :snmp_clone_pdu, [ :pointer ], :pointer
    attach_function :snmp_pdu_type, [ :int ], :string
    attach_function :snmp_pdu_add_variable, [ :pointer, :pointer, :uint, :u_char, :pointer, :size_t ], :pointer, blocking: true
    attach_function :snmp_free_pdu, [ :pointer ], :void, blocking: true
    attach_function :snmp_pdu_create, [:int], :pointer, blocking: true
  
    # session handling
    attach_function :generate_Ku, [:pointer, :int, :string, :int, :pointer, :pointer], :int, blocking: true
    attach_function :snmp_sess_init, [ :pointer ], :void, blocking: true
    attach_function :snmp_sess_open, [ :pointer ], :pointer, blocking: true
    attach_function :snmp_sess_session, [ :pointer ], :pointer, blocking: true
    attach_function :snmp_sess_close, [ :pointer ], :int, blocking: true
  
    # send/receive API
    attach_function :snmp_sess_send, [ :pointer, :pointer ], :int
    attach_function :snmp_sess_async_send, [ :pointer, :pointer, :snmp_callback, :pointer ], :int, blocking: true
    attach_function :snmp_sess_select_info, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :int, blocking: true
    attach_function :snmp_sess_read, [ :pointer, :pointer ], :int, blocking: true
    attach_function :snmp_sess_timeout, [ :pointer ], :void
    attach_function :snmp_sess_synch_response, [:pointer, :pointer, :pointer], :int, blocking: true
  
  
    attach_function :snmp_perror, [ :string ], :void
  
    attach_function :netsnmp_get_version, [], :string
  end
end
