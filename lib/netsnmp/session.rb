# frozen_string_literal: true

module NETSNMP
  # Let's just remind that there is no session in snmp, this is just an abstraction.
  #
  class Session
    TIMEOUT = 2
    DEBUG = ENV.key?("NETSNMP_DEBUG") ? $stderr : nil
    DEBUG_LEVEL = (ENV["NETSNMP_DEBUG"] || 1).to_i

    # @param [Hash] opts the options set
    def initialize(version: 1, community: "public", debug: DEBUG, debug_level: DEBUG_LEVEL, **options)
      @version   = version
      @community = community
      @debug = debug
      @debug_level = debug_level
      validate(**options)
    end

    # Closes the session
    def close
      # if the transport came as an argument,
      # then let the outer realm care for its lifecycle
      @transport.close unless @proxy
    end

    # @param [Symbol] type the type of PDU (:get, :set, :getnext)
    # @param [Array<Hashes>] vars collection of options to generate varbinds (see {NETSMP::Varbind.new} for all the possible options)
    #
    # @return [NETSNMP::PDU] a pdu
    #
    def build_pdu(type, *vars)
      PDU.build(type, headers: [@version, @community], varbinds: vars)
    end

    # send a pdu, receives a pdu
    #
    # @param [NETSNMP::PDU, #to_der] an encodable request pdu
    #
    # @return [NETSNMP::PDU] the response pdu
    #
    def send(pdu)
      log { "sending request..." }
      log(level: 2) { pdu.to_hex }
      encoded_request = pdu.to_der
      log { Hexdump.dump(encoded_request) }
      encoded_response = @transport.send(encoded_request)
      log { "received response" }
      log { Hexdump.dump(encoded_response) }
      response_pdu = PDU.decode(encoded_response)
      log(level: 2) { response_pdu.to_hex }
      response_pdu
    end

    private

    def validate(host: nil, port: 161, proxy: nil, timeout: TIMEOUT, **)
      if proxy
        @proxy = true
        @transport = proxy
      else
        raise "you must provide an hostname/ip under :host" unless host
        @transport = Transport.new(host, port.to_i, timeout: timeout)
      end
      @version = case @version
                 when Integer then @version # assume the use know what he's doing
                 when /v?1/ then 0
                 when /v?2c?/ then 1
                 when /v?3/ then 3
                 else
                   raise "unsupported snmp version (#{@version})"
                 end
    end

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

      message = (+"" << yield << "\n")
      message = "\e[#{COLORS[color]}m#{message}\e[0m" if debug_stream.respond_to?(:isatty) && debug_stream.isatty
      debug_stream << message
    end

    class Transport
      MAXPDUSIZE = 0xffff + 1

      def initialize(host, port, timeout:)
        @socket = UDPSocket.new
        @socket.connect(host, port)
        @timeout = timeout
      end

      def close
        @socket.close
      end

      def send(payload)
        write(payload)
        recv
      end

      def write(payload)
        perform_io do
          @socket.send(payload, 0)
        end
      end

      def recv(bytesize = MAXPDUSIZE)
        perform_io do
          datagram, = @socket.recvfrom_nonblock(bytesize)
          datagram
        end
      end

      private

      def perform_io
        loop do
          begin
            return yield
          rescue IO::WaitReadable
            wait(:wait_readable)
          rescue IO::WaitWritable
            wait(:wait_writable)
          end
        end
      end

      def wait(mode)
        return if @socket.__send__(mode, @timeout)
        raise Timeout::Error, "Timeout after #{@timeout} seconds"
      end
    end
  end
end
