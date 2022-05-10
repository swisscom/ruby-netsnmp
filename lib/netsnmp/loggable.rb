# frozen_string_literal: true

module NETSNMP
  module Loggable
    DEBUG = ENV.key?("NETSNMP_DEBUG") ? $stderr : nil
    DEBUG_LEVEL = ENV.fetch("NETSNMP_DEBUG", 1).to_i

    def initialize_logger(debug: DEBUG, debug_level: DEBUG_LEVEL, **)
      @debug = debug
      @debug_level = debug_level
    end

    private

    COLORS = {
      black: 30,
      red: 31,
      green: 32,
      yellow: 33,
      blue: 34,
      magenta: 35,
      cyan: 36,
      white: 37
    }.freeze

    def log(level: @debug_level)
      return unless @debug
      return unless @debug_level >= level

      debug_stream = @debug

      debug_stream << (+"\n" << yield << "\n")
    end
  end
end
