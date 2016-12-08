module NETSNMP
  module Authentication
    class MD5

      IPAD = "\x36" * 64
      OPAD = "\x5C" * 64

      def initialize(password)
        @password = password
      end

      # http://tools.ietf.org/html/rfc3414#section-6.3.1
      def signature(message, engineid)
        cipher = OpenSSL::Digest::MD5.new
        hmac = OpenSSL::Digest::MD5.new

        key = generate_key(engineid)
        key << "\x00" * 48
        k1 = key.xor(IPAD)
        k2 = key.xor(OPAD)
      
        hmac << ( k1 + message )
        d1 = hmac.digest

        cipher << ( k2 + d1 )
        cipher.digest[0,12]
      end

      private

      def generate_key(engineid="")
        cipher = OpenSSL::Digest::MD5.new
        key = passkey

        cipher << key
        cipher << engineid 
        cipher << key

        cipher.digest
      end

      def passkey
        passkey = OpenSSL::Digest::MD5.new

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
    end
  end
end
