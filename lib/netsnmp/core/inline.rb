module NETSNMP::Core
  module Inline
    if RUBY_PLATFORM == "java"
      def self.oid_size ; FFI::Pointer.size ; end
    else
      require 'inline'
        inline do |builder|
    #      builder.include "sys/select.h"
          builder.include "<net-snmp/net-snmp-config.h>"
          builder.include "<net-snmp/types.h>"
          #builder.include "stdio.h"
          builder.c_singleton %q{
            int oid_size() {
              return sizeof(oid);
            }
          }
      end
    end
  end
end
