# frozen_string_literal: true

module NETSNMP
  module Loggable
    DEBUG = ENV.key?("NETSNMP_DEBUG") ? $stderr : nil
    DEBUG_LEVEL = (ENV["NETSNMP_DEBUG"] || 1).to_i

    def initialize(debug: DEBUG, debug_level: DEBUG_LEVEL, **opts)
      super(**opts)
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

    def log(level: @debug_level, color: nil)
      return unless @debug
      return unless @debug_level >= level

      debug_stream = @debug

      message = (+"\n" << yield << "\n")
      message = "\e[#{COLORS[color]}m#{message}\e[0m" if debug_stream.respond_to?(:isatty) && debug_stream.isatty
      debug_stream << message
    end
  end
end
