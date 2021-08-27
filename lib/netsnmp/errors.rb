# frozen_string_literal: true

module NETSNMP
  class Error < StandardError; end

  class ConnectionFailed < Error; end

  class AuthenticationFailed < Error; end

  class IdNotInTimeWindowError < Error; end
end
