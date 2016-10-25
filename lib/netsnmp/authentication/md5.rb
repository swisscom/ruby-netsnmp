module NETSNMP
  module Authentication
    module MD5
      extend self

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

      # http://tools.ietf.org/html/rfc3414#section-7.3.1
      def generate_param(authkey, message)
        cipher = OpenSSL::Digest::MD5.new
        md5mac = OpenSSL::Digest::MD5.new

        key = authkey
        key << "\x00" * 48
        k1 = key.xor("\x36" * 64)
        k2 = key.xor("\x5C" * 64)
      
        md5mac << k1
        md5mac << message
        dig = md5mac.digest

        cipher << k2
        cipher << dig
        cipher.digest[0,12]
      end
    end
  end
end
