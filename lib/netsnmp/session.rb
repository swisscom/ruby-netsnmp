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
      # For now, let's eager load the signature
#      @signature = build_signature(@options)
#      if @signature.null?
#        raise ConnectionFailed, "could not build signature for #@hostname"
#      end
      @requests ||= {}
    end

    # Closes the session
    def close
      @transport.close if defined?(@transport)
#      return unless @signature
#      if @transport
#        transport.close rescue nil
#      end
#      if Core::LibSNMP.snmp_sess_close(@signature) == 0
#        raise Error, "#@hostname: Couldn't clean up session properly"
#      end
    end

    def build_pdu(type, options=@options)
      pdu = PDU.build(type, options)
      yield pdu if block_given?
      if options[:version] == 3
        message = snmp3_message(pdu, options)
        auth_param = authentication.generate_param(message)
        message.set_auth_param(auth_param)

        return message
      end
      pdu
    end 


    # sends a request PDU and waits for the response
    # 
    # @param [RequestPDU] pdu a request pdu
    # @param [Hash] opts additional options
    # @option opts [true, false] :async if true, it doesn't wait for response (defaults to false)
    def send(pdu, options=@options)
#      if !options[:engine_id]
#        options = snmp3_options(pdu, options)
#      end
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
      options[:community] ||= "public" # v1/v2 default community
      options[:timeout] ||= 10
      options[:retries] ||= 5
      options
    end

    def snmp3_message(pdu, options)
      pdu_type = pdu.type
      probe_message = probe_for_engine(pdu, options)

      options[:security_level] = case options[:security_level]
        when /noauth/           then 0
        when /auth_?no_?priv/   then 1
        when /auth_?priv/, nil  then 3
        when Integer
          options[:security_level]
      end

      probe_message.pdu.from_pdu(pdu)
      probe_message
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
                                    security_level: 0,
                                    priv_protocol: nil,
                                    auth_protocol: nil,
                                    engine_time: 0, version: 1, pdu: pdu)
      message = Message.new(probe_options)
      send(message, options)
    end
#
#    def handle_response
#      operation, response_pdu = @requests.delete(@reqid)
#      case operation
#        when :success
#          response_pdu
#        when :send_failed
#          raise ReceiveError, "#@hostname: Failed to receive pdu"
#        when :timeout
#          raise Timeout::Error, "#@hostname: timed out while waiting for pdu response"
#        else
#          raise Error, "#@hostname: unrecognized operation for request #{@reqid}: #{operation} for #{response_pdu}"
#      end
#    end
#
#    def receive
#      readers, _ = try_login { wait_readable }
#      case readers.size
#        when 1..Float::INFINITY
#          # triggers callback
#          async_read
#        when 0
#          Core::LibSNMP.snmp_sess_timeout(@signature)
#        else
#          raise ReceiveError, "#@hostname: error receiving data"
#      end
#    end
#    
#    def async_read
#      if Core::LibSNMP.snmp_sess_read(@signature, get_selectable_sockets.pointer) != 0
#        # if it's the first time we're passing here and send fails, we can (?) assume that
#        # PRIV_PASSWORD is wrong
#        if @logged_at.nil?
#          raise ConnectionFailed, "failed to login to #@hostname"
#        else
#          raise ReceiveError, "#@hostname: Failed to receive pdu response"
#        end
#      end
#    end
#
#    def timeout
#      Core::LibSNMP.snmp_sess_timeout(@signature)
#    end
#
#    def wait_writable
#      IO.select([],[transport])
#    end
#
#    def wait_readable
#      IO.select([transport])
#    end
#
#    def get_selectable_sockets
#      fdset = Core::C::FDSet.new
#      fdset.clear
#      num_fds = FFI::MemoryPointer.new(:int)
#      tv_sec = 0
#      tv_usec = 0
#      tval = Core::C::Timeval.new
#      tval[:tv_sec] = tv_sec
#      tval[:tv_usec] = tv_usec
#      block = FFI::MemoryPointer.new(:int)
#      block.write_int(0)
#      Core::LibSNMP.snmp_sess_select_info(@signature, num_fds, fdset.pointer, tval.pointer, block )
#      fdset
#    end


    # @param [Core::Structures::Session] session the snmp session structure
    # @param [Hash] options session options with authorization parameters
    # @option options [String] :version the snmp protocol version (if < 3, forget the rest)
    # @option options [Integer, nil] :security_level the SNMP security level (defaults to authPriv)
    # @option options [Symbol, nil] :auth_protocol the authorization protocol (ex: :md5, :sha1)
    # @option options [Symbol, nil] :priv_protocol the privacy protocol (ex: :aes, :des)
    # @option options [String, nil] :context the authoritative context 
    # @option options [String] :version the snmp protocol version (defaults to 3, if not 3, you actually don't need the rest)
    # @option options [String] :username the username to login with
    # @option options [String] :auth_password the authorization password
    # @option options [String] :priv_password the privacy password
#    def session_authorization(session, options)
#      # we support version 3 by default      
#      session[:version] = case options[:version]
#        when /v?1/ then  Core::Constants::SNMP_VERSION_1
#        when /v?2c?/ then  Core::Constants::SNMP_VERSION_2c
#        when /v?3/, nil then Core::Constants::SNMP_VERSION_3
#      end
#      return unless session[:version] == Core::Constants::SNMP_VERSION_3 
#
#
#      session[:securityAuthProtoLen] = 10
#      session[:securityAuthKeyLen] = Core::Constants::USM_AUTH_KU_LEN
#      session[:securityPrivProtoLen] = 10
#      session[:securityPrivKeyLen] = Core::Constants::USM_PRIV_KU_LEN
#
#      # Security Authorization
#      session[:securityLevel] =  case options[:security_level] 
#        when /noauth/         then Core::Constants::SNMP_SEC_LEVEL_NOAUTH
#        when /auth_?no_?priv/ then Core::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV
#        when /auth_?priv/     then Core::Constants::SNMP_SEC_LEVEL_AUTHPRIV 
#        when Integer
#          options[:security_level]
#        else Core::Constants::SNMP_SEC_LEVEL_AUTHPRIV
#      end
#
#      auth_protocol_oid = case options[:auth_protocol]
#        when :md5   then MD5OID.new
#        when :sha1  then SHA1OID.new
#        when nil    then NoAuthOID.new
#        else raise Error, "#@hostname: #{options[:auth_protocol]} is an unsupported authorization protocol"
#      end
#
#       # Priv Protocol
#      priv_protocol_oid = case options[:priv_protocol]
#        when :aes then AESOID.new 
#        when :des then DESOID.new
#        when nil  then NoPrivOID.new
#        else raise Error, "#@hostname: #{options[:priv_protocol]} is an unsupported privacy protocol"
#      end
#   
#      user, auth_pass, priv_pass = options.values_at(:username, :auth_password, :priv_password)
#      auth_protocol_oid.generate_key(session, user, auth_pass)
#      priv_protocol_oid.generate_key(session, user, priv_pass )
#
#      if options[:context]
#        session[:contextName] = FFI::MemoryPointer.from_string(options[:context])
#        session[:contextNameLen] = options[:context].length
#      end
#
#
#    end


    # @param [Hash] options options to open the net-snmp session
    # @option options [String] :community the snmp community string (defaults to public)
    # @option options [Integer] :timeout number of sec until first timeout
    # @option options [Integer] :retries number of retries before timeout
    # @return [FFI::Pointer] a pointer to the validated session signature, which will therefore be used in all _sess_ methods from libnetsnmp
#    def build_signature(options)
#      # allocate new session
#      session = Core::Structures::Session.new(nil)
#      Core::LibSNMP.snmp_sess_init(session.pointer)
#
#      # initialize session
#      if options[:community]
#        community = options[:community]
#        session[:community] = FFI::MemoryPointer.from_string(community)
#        session[:community_len] = community.length
#      end
#      
#      peername = host
#      unless peername[':']
#        port = options[:port] || '161'.freeze
#        peername = "#{peername}:#{port}"
#      end 
#      
#      session[:peername] = FFI::MemoryPointer.from_string(peername)
#
#      @timeout = options[:timeout] || 10
#      session[:timeout] = @timeout * 1000000
#      session[:retries] = options[:retries] || 5
#      session_authorization(session, options)
#      Core::LibSNMP.snmp_sess_open(session.pointer)
#    end

#    def fetch_transport
#      return unless @signature
#      list = Core::Structures::SessionList.new @signature
#      return if not list or list.pointer.null?
#      t = Core::Structures::Transport.new list[:transport]
#      IO.new(t[:sock]) 
#    end
#
#    # @param [Core::Structures::Session] session the snmp session structure
#    def session_callback
#      @callback ||= FFI::Function.new(:int, [:int, :pointer, :int, :pointer, :pointer]) do |operation, session, reqid, pdu_ptr, magic|
#        op = case operation
#          when Core::Constants::NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE then :success
#          when Core::Constants::NETSNMP_CALLBACK_OP_TIMED_OUT then :timeout
#          when Core::Constants::NETSNMP_CALLBACK_OP_SEND_FAILED then :send_failed
#          when Core::Constants::NETSNMP_CALLBACK_OP_CONNECT then :connect
#          when Core::Constants::NETSNMP_CALLBACK_OP_DISCONNECT then :disconnect
#          else :unrecognized_operation 
#        end
#
#
#        # TODO: pass exception in case of failure
#
#        response_pdu = ResponsePDU.new(pdu_ptr)
#        @requests[@reqid] = [op, response_pdu]
#        if reqid == @reqid
#          # probably pass the result as a yield from a fiber
#          op.eql?(:unrecognized_operation) ? 0 : 1
#        else  
#          # this is happening when user is unknown(????)
#          #puts "wow, unexpected #{op}.... #{reqid} different than #{@reqid}"
#          0
#        end
#      end
#
#    end
  end
end
