module NETSNMP
  module Authentication
    class MD5

      def initialize(password)
        @password = password
      end

      # http://tools.ietf.org/html/rfc3414#section-6.3.1
      def generate_param(message)
        cipher = OpenSSL::Digest::MD5.new
        md5mac = OpenSSL::Digest::MD5.new

        key = generate_key(message.options[:engine_id])
        key << "\x00" * 48
        k1 = key.xor("\x36" * 64)
        k2 = key.xor("\x5C" * 64)
      
        md5mac << k1
        md5mac << message.to_der
        dig = md5mac.digest

        cipher << k2
        cipher << dig
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
          64.times do
            buffer << @password[password_index % password_length]
            password_index += 1
          end
          passkey << buffer
          buffer.clear
          count += 64
        end
        passkey.digest
      end
    end
  end
end
