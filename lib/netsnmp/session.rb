module NETSNMP
  # Let's just remind that there is no session in snmp, this is just an abstraction. 
  # 
  class Session

    attr_reader :host, :signature

    # @param [String] host the host IP/hostname
    # @param [Hash] opts the options set 
    #
    def initialize(host, opts)
      @host = host
      @port = (opts.delete(:port) || 161).to_i
      @options = validate_options(opts)
      @logged_at = nil
    end

    # Closes the session
    def close
      @transport.close if defined?(@transport)
    end

    def build_pdu(type, *oids)
      PDU.build(type, headers: @options.values_at(:version, :community), varbinds: oids)
    end


    # sends a request PDU and waits for the response
    # 
    # @param [RequestPDU] pdu a request pdu
    def send(pdu)
      write(pdu)
      read(pdu)
    end

    private

    def validate_options(options)
      version = options[:version] = case options[:version]
        when Integer then options[:version] # assume the use know what he's doing
        when /v?1/ then 0 
        when /v?2c?/ then 1 
        when /v?3/, nil then 3
      end

      options[:community] ||= "public" # v1/v2 default community
      options[:timeout] ||= 10
      options[:retries] ||= 5
      options
    end


    def transport
      @transport ||= begin
        tr = UDPSocket.new
        tr.connect( @host, @port )
        tr
      end
    end

    # encodes the message and writes it over the wire
    #
    # @param [NETSNMP::PDU, NETSNMP::Message] pdu a valid pdu (version 1/2) or message (v3)
    # @param [Hash] opts additional options
    #
    def write(pdu)
      perform_io do
        transport.send( encode(pdu), 0 )
      end
    end

    MAXPDUSIZE = 0xffff + 1

    # reads from the wire and decodes
    #
    # @param [NETSNMP::PDU, NETSNMP::Message] request_pdu or message which originated the response
    # @param [Hash] options additional options
    #
    # @return [NETSNMP::PDU, NETSNMP::Message] the response pdu or message
    #
    def read(request_pdu)
      perform_io do
        datagram , _ = transport.recvfrom_nonblock(MAXPDUSIZE)
        @logged_at ||= Time.now
        decode(datagram, request_pdu)
      end
    end


    def perform_io
      loop do
        begin
          return yield
        rescue IO::WaitReadable
          wait(:r)
        rescue IO::WaitWritable
          wait(:w)
        end
      end
    end


    def wait(mode, timeout: @options[:timeout])
      meth = case mode
        when :r then :wait_readable
        when :w then :wait_writable
      end
      unless transport.__send__(meth, timeout)
        raise TimeoutError, "Timeout after #{timeout} seconds"
      end   
    end

    def encode(pdu)
      return pdu.to_der
    end

    def decode(stream, request)
      PDU.decode(stream)
    end
  end
end
