module NETSNMP::Core
  module C
    extend FFI::Library
    ffi_lib(FFI::Library::LIBC).first
  
    typedef :pointer, :FILE
    typedef :uint32, :in_addr_t
    typedef :uint16, :in_port_t
  
    unless FFI::Platform::IS_WINDOWS
      attach_function :getdtablesize, [], :int
    end
  
    class Timeval < FFI::Struct
      if FFI::Platform::IS_WINDOWS
        layout(
          :sec, :long,  
          :usec, :long
        )
      else
        layout(
          :tv_sec, :time_t,
          :tv_usec, :suseconds_t
        )
      end
    end
  
    class FDSet < ::FFI::Struct
      if FFI::Platform::IS_WINDOWS
        layout(
          :fd_count, :uint,
          # TODO: Make it future proof by dynamically grabbing FD_SETSIZE.
          :fd_array, [:uint, 2048]
        )
        def clear; self[:fd_count] = 0; end
      else
        # FD Set size.
        FD_SETSIZE = C.getdtablesize
        layout(
          :fds_bits, [:long, FD_SETSIZE / FFI::Type::LONG.size]
        )
  
        # :nodoc:
        def clear; super; end
      end
    end
  
    # Standard IO functions
    #@blocking = true  # some undocumented voodoo that tells the next attach_function to release the GIL
    attach_function :malloc, [:size_t], :pointer
    attach_function :calloc, [:size_t, :size_t], :pointer
    attach_function :memcpy, [:pointer, :pointer, :size_t], :pointer
    attach_function :free, [:pointer], :void

  end
end
