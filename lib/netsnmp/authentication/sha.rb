module NETSNMP
  module Authentication
    class SHA
      IPAD = "\x36" * 64
      OPAD = "\x5c" * 64
     
      attr_reader :localized_key

      def initialize(password, engine_id)
        @password = password
        @localized_key = generate_key(engine_id)
      end

      # http://tools.ietf.org/html/rfc3414#section-7.3.1
      def signature(message, engineid)
        cipher = OpenSSL::Digest::SHA1.new
        hmac = OpenSSL::Digest::SHA1.new 

        key = @localized_key.dup

        key << "\x00" * 44 
        k1 = key.xor(IPAD)
        k2 = key.xor(OPAD)

        hmac << ( k1 + message )
        d1 = hmac.digest

        cipher << ( k2 + d1 )
        cipher.digest[0,12]
      end

      def passkey
        passkey = OpenSSL::Digest::SHA1.new

        password_index = 0
        count = 0

        buffer = String.new
        password_length = @password.length
        while count < 1048576
          initial = password_index % password_length
          rotated_password = @password[initial..-1] + @password[0,initial]
          buffer << rotated_password while buffer.length < 64
          password_index += 64
          passkey << buffer[0,64]
          buffer.clear
          count += 64
        end
        passkey.digest

      end

      private

      def generate_key(engineid="")
        cipher = OpenSSL::Digest::SHA1.new

        key = passkey
        cipher << key
        cipher << engineid
        cipher << key
        cipher.digest
      end

    end
  end
end

