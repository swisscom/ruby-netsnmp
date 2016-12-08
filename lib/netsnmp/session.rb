module NETSNMP
  # The Entity abstracts the C net-snmp session, and the lifecycle steps.
  # 
  # For example, a session must be initialized (memory allocated) and opened 
  # (authentication, encryption, signature)
  #
  # The session uses the signature to send and receive PDUs. They are built somewhere else.
  # 
  # After the session is established, a socket handle is read from the structure. This will
  # be later used for non-blocking behaviour. It's important to notice, there is no
  # usage of the C net-snmp sync API, we always do async send/response, even if the 
  # ruby API "feels" blocking. This was done so that the GIL can be released between
  # sends and receives, and the load can be shared through different threads possibly. 
  # As we use the session abstraction, this means we ONLY use the thread-safe API. 
  #
  class Session

    attr_reader :host, :signature

    # @param [String] host the host IP/hostname
    # @param [Hash] opts the options set 
    # 
    def initialize(host, opts)
      @host = host
      # this is because other evented clients might discover IP first, but hostnames
      # give you better trackability of errors. Give the opportunity to the users to
      # pass it, by setting the hostname explicitly. If not, fallback to the host. 
      @hostname = opts.delete(:hostname) || @host
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
      if options[:version] == 3
        return snmp3_message(pdu, options)
      end
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

    def validate_options(options)
      version = options[:version] = case options[:version]
        when Integer then options[:version] # assume the use know what he's doing
        when /v?1/ then 0 
        when /v?2c?/ then 1 
        when /v?3/, nil then 3
      end

      options[:security_level] = case options[:security_level]
        when /noauth/           then 0
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

    def snmp3_message(pdu, options)
      probe_message = probe_for_engine(pdu, options)
      
      message = Message.new(options.merge(pdu: pdu))
      message.from_message(probe_message)
      message
    end

    def authentication
      @authentication ||= case @options[:auth_protocol]
      when /md5/
        Authentication::MD5.new(@options[:auth_password])
      when /aes/
        raise
      else
        Authentication::None.new 
      end
    end

    def transport
      @transport ||= begin
        tr = UDPSocket.new
        tr.connect( @host, @port )
        tr
      end
    end

    def write(pdu, **opts)
      perform_io do
        transport.send( encode(pdu, **opts), 0 )
      end
    end

    MAXPDUSIZE = 65536 

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

    private

    def encode(pdu, options=@options)
      return pdu.to_der
    end

    def decode(stream, request, options=@options)
      message = options[:version] == 3 ?
                Message.new(encryption: request.encryption) : 
                PDU.new
      message.decode(stream)
      message
    end

    def probe_for_engine(pdu, options)
      probe_options = options.merge(engine_id: "",
                                    engine_boots: 0,
                                    username: "",
                                    priv_protocol: nil,
                                    auth_protocol: nil,
                                    security_level: 0,
                                    engine_time: 0, pdu: pdu)
      message = Message.new(probe_options)
      send(message, options)
    end


  end
end
