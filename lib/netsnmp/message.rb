module NETSNMP
  # Factory for the SNMP v3 Message format
  class Message
    MSG_ID             = OpenSSL::ASN1::Integer.new(56219466)
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3)           # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3)
    MSG_REPORTABLE     = 4

    extend Forwardable 
    def_delegators :@pdu, :add_varbind, :[], :[]=

#    class << self
#      private
#      def encrypt(pdu, options)
#        case options[:priv_protocol]
#        when /des/
#          encrypted_pdu, salt = Encryption::DES.encode(pdu.to_der, options[:priv_password], options)
#          [OpenSSL::ASN1::OctetString.new(encrypted_pdu), salt]
#        when /aes/
#          raise
#        else
#          pdu
#        end
#      end
#
#      def authenticate(pdu, options)
#        message = new(options.merge(pdu: pdu))
#        case options[:auth_protocol]
#        when /md5/
#          auth_key = Authentication::MD5.generate_key(options[:auth_password], options[:engine_id])
#          auth_param = Authentication::MD5.generate_param(auth_key, message.to_der)
#        when /sha/
#        else
#        end
#        auth_param = auth_param.unpack("H*").join
#        new(options.merge(pdu: pdu, auth_param: auth_param))
#      end
#
#    end

    attr_reader :pdu, :options

    def initialize(options={}) 
      @pdu = options.delete(:pdu)
      @encryption = options.delete(:encryption)
      @options = options

#      @auth_param = options[:auth_param] || ("\x00" * 12)
#      @priv_param = options[:priv_param] || ""
    end

    def to_asn
      encrypted = encrypt_pdu
      OpenSSL::ASN1::Sequence([ 
        MSG_VERSION, 
        encode_headers_asn,
        OpenSSL::ASN1::OctetString.new(encode_security_parameters_asn(pdu).to_der),
        encrypted])
    end

    def to_der
      to_asn.to_der
    end

    def decode(der)
      asn_tree = OpenSSL::ASN1.decode(der)
      version, headers, security_parameters, pdu_payload = asn_tree.value
      decode_security_parameters_asn(security_parameters.value)

      pdu_der= encryption.decrypt(pdu_payload, @priv_param)
      
      @pdu = PDU.new
      @pdu.decode(pdu_der)
    end


    def authentication
      @authentication ||= case options[:auth_protocol]
      when /md5/
        Authentication::MD5.new(options[:auth_password], options[:engine_id])
      when /aes/
        raise
      else
        Authentication::None.new 
      end
    end

    def encryption
      @encryption ||= case options[:priv_protocol]
      when /des/
        Encryption::DES.new(options[:priv_password], options[:engine_boots])
      when /aes/
        raise
      else
        Encryption::None.new
      end
    end

    private
    def encode_headers_asn
      message_flags = MSG_REPORTABLE | (@options[:security_level] || 0)
      OpenSSL::ASN1::Sequence.new([
        MSG_ID, MSG_MAX_SIZE,
        OpenSSL::ASN1::OctetString.new( [String(message_flags)].pack("h*") ),
        MSG_SECURITY_MODEL
      ])
    end

    def encode_security_parameters_asn(encrypted_pdu)
      @priv_param = encryption.salt
      @auth_param = authentication.generate_param(encrypted_pdu.to_der)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(@options[:engine_id]),
        OpenSSL::ASN1::Integer.new(@options[:engine_boots]),
        OpenSSL::ASN1::Integer.new(@options[:engine_time]),
        OpenSSL::ASN1::OctetString.new(@options[:username]),
        OpenSSL::ASN1::OctetString.new(@auth_param),
        OpenSSL::ASN1::OctetString.new(@priv_param)
      ])
    end

    def decode_security_parameters_asn(der)
      asn_tree = OpenSSL::ASN1.decode(der).value

      @options[:engine_id] = asn_tree[0].value
      @options[:engine_boots] = asn_tree[1].value.to_i
      @options[:engine_time] = asn_tree[2].value.to_i
      @options[:username] = asn_tree[3].value
      @auth_param = asn_tree[4].value
      @priv_param = asn_tree[5].value

    end

    def encrypt_pdu
      encryption.encrypt(@pdu)
    end
  end
end
