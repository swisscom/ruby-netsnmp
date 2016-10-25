module NETSNMP
  module Encryption
    module DES
      extend self
      SALTLSB = Random.new.bytes(4)


      def encode(pdu, password, **options)
        engineboots = options.fetch(:engine_boots, "")
        cipher = OpenSSL::Cypher::DES.new(:CBC)

        # https://tools.ietf.org/html/rfc3414#section-8.1.1.1
        if engineboots.size < 4
          engineboots = ( "\x00" * ( 4 - engineboots.size) ) <<
                          [engineboots].pack("H*")
        end

        des_key = generate_key(password)

        prev_iv = password[4, 4]
        salt = engineboots[0, 4]
        salt << SALTLSB
        iv = sal.xor(prev_iv)

        # get cipher
        cipher.encrypt
        cipher.key = des_key
        cipher.iv = iv
        encrypted = cipher.update(pdu) + cipher.final
        [encrypted, salt]
      end


      def generate_key(password)
        passstream = password.unpack("B*").flat_map(&:chars)
        octets = passstream.length / 8
        while octets > 0
          passstream.delete_at(octets * 8 - 1)
          octets -= 1
        end
        des_key = "\x00" << [passstream.join].pack("B*")
      end
    end
  end
end
