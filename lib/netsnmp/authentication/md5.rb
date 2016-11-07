module NETSNMP
  module Authentication
    class MD5

      def initialize(password)
        @password = password
      end

      # http://tools.ietf.org/html/rfc3414#section-7.3.1
      def generate_param(message)
        cipher = OpenSSL::Digest::MD5.new
        md5mac = OpenSSL::Digest::MD5.new

        key = generate_key(@password, message.options[:engine_id])
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

      def generate_key(password, engineid="")
        cipher = OpenSSL::Digest::MD5.new
        passkey = OpenSSL::Digest::MD5.new

        password_length = password.length
        buffer = String.new
        64.times { |i| buffer << i % password_length }
        passkey << buffer * (1048576 / 64)
        passdigest = passkey.digest

        cipher << passdigest
        cipher << engineid 
        cipher << passdigest

        cipher.digest
      end

    end
  end
end
