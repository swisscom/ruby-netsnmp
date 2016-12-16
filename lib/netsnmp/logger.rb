# frozen_string_literal: true
require 'logger'

module NETSNMP 
  class << self
    attr_accessor :logger
  end

  # Logger class that allows us to access (and replace) the log device
  # +logdev+.
  class Logger < ::Logger
    attr_accessor :logdev

    # SEM specific formatter
    FORMATTER = proc do |severity, datetime, progname, msg|
      "SNMP#{progname && " <#{progname}>"} #{severity}: #{msg}\n"
    end
  end

  self.logger = Logger.new($stderr)
  self.logger.formatter = Logger::FORMATTER
  self.logger.level = $DEBUG ? Logger::DEBUG : Logger::INFO

  # DRY up deprecation warnings.
  #
  # @example
  #   def deprecated_method
  #     SEM.deprecated "Don't use #{__method__} anymore. Use #better_method instead."
  #   end
  module DeprecationWarnings
    # Use this method to warn about something deprecated. It'll use the current
    # {SEM.logger} and log the current callstack as well.
    def deprecated(msg)
      SEM.logger.warn "DEPRECATION WARNING: #{msg}\n#{caller.join("\n")}"
    end
  end
  extend DeprecationWarnings
end
