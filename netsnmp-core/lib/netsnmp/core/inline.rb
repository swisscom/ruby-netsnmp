require 'inline'
module NETSNMP::Core
  module Inline
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
