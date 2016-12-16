# frozen_string_literal: true
require 'ffi'

require 'netsnmp/core/libc'
require 'netsnmp/core/constants'
require 'netsnmp/core/structures'
require 'netsnmp/core/libsnmp'
require 'netsnmp/core/inline'
require 'netsnmp/core/utilities'

module NETSNMP::Core
  LibSNMP.init_snmp("snmp")
end
