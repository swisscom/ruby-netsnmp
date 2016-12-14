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
      @request = nil
      @requests ||= {}
    end

    # Closes the session
    def close
      @transport.close if defined?(@transport)
    end

    def build_pdu(type, options=@options)
      pdu = PDU.build(type, options)
      return build_message(pdu, options) if options[:version] == 3
      pdu
    end


    # sends a request PDU and waits for the response
    # 
    # @param [RequestPDU] pdu a request pdu
    # @param [Hash] opts additional options
    # @option opts [true, false] :async if true, it doesn't wait for response (defaults to false)
    def send(pdu, options=@options)
      write(pdu, options)
      read(pdu, options)
    end

    private

    # TODO: throw error when authpass < 8 bytes
    # TODO: throw Error when privpass < 8 bytes
    def validate_options(options)
      version = options[:version] = case options[:version]
        when Integer then options[:version] # assume the use know what he's doing
        when /v?1/ then 0 
        when /v?2c?/ then 1 
        when /v?3/, nil then 3
      end

      options[:security_level] = case options[:security_level]
        when /no_?auth/         then 0
        when /auth_?no_?priv/   then 1
        when /auth_?priv/, nil  then 3
        when Integer
          options[:security_level]
      end

      options[:community] ||= "public" # v1/v2 default community
      options[:timeout] ||= 10
      options[:retries] ||= 5
      options
    end

    #
    # @param [NETSNMP::PDU] pdu the scoped pdu
    # @param [Hash] options additional options
    #
    # @return [NETSNMP::Message] a prepared v3 Message
    #
    def build_message(pdu, options)
      probe_message = probe_for_engine(pdu, options)
      
      message = Message.new(pdu, options)
      message.from_message(probe_message)
      message
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
    def write(pdu, **opts)
      perform_io do
        transport.send( encode(pdu, **opts), 0 )
      end
    end

    MAXPDUSIZE = 65536 

    # reads from the wire and decodes
    #
    # @param [NETSNMP::PDU, NETSNMP::Message] request_pdu or message which originated the response
    # @param [Hash] options additional options
    #
    # @return [NETSNMP::PDU, NETSNMP::Message] the response pdu or message
    #
    def read(request_pdu, options=@options)
      perform_io do
        datagram , _ = transport.recvfrom_nonblock(MAXPDUSIZE)
        @logged_at ||= Time.now
        decode(datagram, request_pdu, options)
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

    def encode(pdu, options=@options)
      return pdu.to_der
    end

    def decode(stream, request, options=@options)
      message = options[:version] == 3 ?
                Message.new(PDU.new, encryption: request.encryption) : 
                PDU.new
      message.decode(stream)
      message
    end

    # sends a probe snmp v3 request, to get the additional info with which to handle the security aspect
    #
    # @param [NETSNMP::PDU] pdu the scoped pdu to send
    # @param [Hash] message options
    #
    # @return [NETSNMP::Message] the response snmp v3 message with the agent parameters (engine id, boots, time)
    def probe_for_engine(pdu, options)
      probe_options = options.merge(engine_id: "",
                                    engine_boots: 0,
                                    username: "",
                                    priv_protocol: nil,
                                    auth_protocol: nil,
                                    security_level: 0,
                                    engine_time: 0)
      message = Message.new(pdu, probe_options)
      send(message, options)
    end


  end
end
