# frozen_string_literal: true

module NETSNMP
  Error = Class.new(StandardError)
  ConnectionFailed = Class.new(Error)
  AuthenticationFailed = Class.new(Error)
end
