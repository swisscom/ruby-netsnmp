module NETSNMP
  class SecurityParameters

    IPAD = "\x36" * 64
    OPAD = "\x5c" * 64

    attr_reader :security_level, :username, :engine_id
    def initialize(security_level: , 
                   username: , 
                   engine_id: "",
                   auth_protocol: nil, 
                   auth_password: nil, 
                   priv_protocol: nil, 
                   priv_password: nil)
      @security_level = security_level
      @username = username
      @engine_id = engine_id
      @auth_protocol = auth_protocol.to_sym unless auth_protocol.nil?
      @priv_protocol = priv_protocol.to_sym unless priv_protocol.nil?
      @auth_password = auth_password
      @priv_password = priv_password
      check_parameters
    end

    def auth_key
      @auth_key ||= localize_key(@auth_password)
    end

    def priv_key
      @priv_key ||= localize_key(@priv_password)
    end


    def encode(pdu, salt: , engine_time: , engine_boots: )
      if encryption
        encrypted_pdu, salt = encryption.encrypt(pdu.to_der, engine_boots: engine_boots, 
                                                             engine_time: engine_time)
        [OpenSSL::ASN1::OctetString.new(encrypted_pdu), OpenSSL::ASN1::OctetString.new(salt) ]
      else
        [ pdu.to_asn, salt ]
      end
    end

    def decode(der, salt: , engine_time: , engine_boots: )
      asn = OpenSSL::ASN1.decode(der)
      if encryption
        encrypted_pdu = asn.value
        pdu_der = encryption.decrypt(encrypted_pdu, salt: salt, engine_time: engine_time, engine_boots: engine_boots)
        OpenSSL::ASN1.decode(pdu_der)      
      else
        asn
      end
    end

    def sign(message)
      # don't sign unless you have to
      return nil if not @auth_protocol

      key = auth_key.dup

      key << "\x00" * (@auth_protocol == :md5 ? 48 : 44)
      k1 = key.xor(IPAD)
      k2 = key.xor(OPAD)

      digest.reset
      digest << ( k1 + message )
      d1 = digest.digest

      digest.reset
      digest << ( k2 + d1 )
      digest.digest[0,12]
    end

    private

    def check_parameters
      @security_level = case @security_level
        when Integer then @security_level
        when /no_?auth/         then 0
        when /auth_?no_?priv/   then 1
        when /auth_?priv/, nil  then 3
        else
          raise Error, "security level not supported: #{@security_level}"
      end

      if @security_level > 0
        @auth_protocol ||= :md5 # this is the default
        raise "security level requires an auth password" if @auth_password.nil?
        raise "auth password must have between 8 to 32 characters" if not (8..32).include?(@auth_password.length)
      end
      if @security_level > 1
        @priv_protocol ||= :des
        raise "security level requires a priv password" if @priv_password.nil?
        raise "priv password must have between 8 to 32 characters" if not (8..32).include?(@priv_password.length)
      end
    end

    def localize_key(password)
      key = passkey(password)

      digest.reset
      digest << key
      digest << @engine_id 
      digest << key

      digest.digest
    end

    def passkey(password)

      digest.reset
      password_index = 0
      count = 0

      buffer = String.new
      password_length = password.length
      while count < 1048576
        initial = password_index % password_length
        rotated_password = password[initial..-1] + password[0,initial]
        buffer << rotated_password while buffer.length < 64
        password_index += 64
        digest << buffer[0,64]
        buffer.clear
        count += 64
      end

      dig = digest.digest
      dig = dig[0,16] if @auth_protocol == :md5
      dig
    end

    def digest 
      @digest ||= case @auth_protocol
      when :md5 then OpenSSL::Digest::MD5.new
      when :sha then OpenSSL::Digest::SHA1.new
      else 
        raise Error, "unsupported auth protocol: #{@auth_protocol}"
      end
    end

    def encryption
      @encryption ||= case @priv_protocol
      when :des
        Encryption::DES.new(priv_key)
      when :aes
        Encryption::AES.new(priv_key)
      end
    end

  end
end
