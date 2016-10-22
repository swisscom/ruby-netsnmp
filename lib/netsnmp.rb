require "netsnmp/version"
require "openssl"

# core structures
require 'netsnmp/core'

module NETSNMP
  # @return [String] the version of the netsnmp C library
  def self.version ; Core.version ; end
end

require "netsnmp/ber"
require "netsnmp/errors"
require "netsnmp/varbind"
require "netsnmp/oid"
require "netsnmp/pdu"
require "netsnmp/session"
require "netsnmp/client"
