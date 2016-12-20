# frozen_string_literal: true
module NETSNMP
  # Let's just remind that there is no session in snmp, this is just an abstraction. 
  # 
  class Session
    TIMEOUT = 2

    # @param [Hash] opts the options set 
    def initialize(opts)
      @options = validate_options(opts)
    end

    # Closes the session
    def close
      # if the transport came as an argument,
      # then let the outer realm care for its lifecycle
      @transport.close unless @options.has_key?(:proxy)
    end

    def build_pdu(type, *oids)
      PDU.build(type, headers: @options.values_at(:version, :community), varbinds: oids)
    end


    def send(pdu)
      encoded_request = encode(pdu) 
      encoded_response = @transport.send(encoded_request)
      decode(encoded_response)
    end

    private

    def validate_options(options)
      options[:community] ||= "public" # v1/v2 default community

      proxy = options[:proxy]
      if proxy
        @transport = proxy 
      else
        host, port = options.values_at(:host, :port)
        raise "you must provide an hostname/ip under :host" unless host
        port ||= 161 # default snmp port
        @transport = Transport.new(host, port.to_i, timeout: options.fetch(:timeout, TIMEOUT))
      end
      version = options[:version] = case options[:version]
        when Integer then options[:version] # assume the use know what he's doing
        when /v?1/ then 0 
        when /v?2c?/ then 1 
        when /v?3/, nil then 3
      end

      options
    end


    def encode(pdu)
      pdu.to_der
    end

    def decode(stream)
      PDU.decode(stream)
    end

    class Transport
      MAXPDUSIZE = 0xffff + 1

      def initialize(host, port, timeout: )
        @socket = UDPSocket.new
        @socket.connect( host, port )
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

      def recv(bytesize=MAXPDUSIZE)
        perform_io do
          datagram, _ = @socket.recvfrom_nonblock(bytesize)
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
        unless @socket.__send__(mode, @timeout)
          raise Timeout::Error, "Timeout after #{@timeout} seconds"
        end   
      end

    end
  end
end
