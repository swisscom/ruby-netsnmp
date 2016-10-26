module NETSNMP
  module Encryption
    class DES < None
      SALTLSB = Random.new.bytes(4)

      def initialize(password, engineboots)
        super
        # https://tools.ietf.org/html/rfc3414#section-8.1.1.1
        boots_str = [engineboots.to_s].pack("H*")
        while boots_str.size < 4
          boots_str.prepend("\x00")
        end

        @des_key = generate_key(password)

        prev_iv = password[4, 4]
        @salt = boots_str[0, 4]
        @salt << SALTLSB
        @iv = salt.xor(prev_iv)
      end

      def encrypt(pdu)
        cipher = OpenSSL::Cipher::DES.new(:CBC)
        # get cipher
        cipher.encrypt
        cipher.key = @des_key
        cipher.iv = @iv
        payload = cipher.update(pdu.to_der) + cipher.final
        OpenSSL::ASN1::OctetString.new(payload)
      end


      def decrypt(stream, priv_salt)
        seq = stream.value
        raise unless seq % 8 == 0

        decipher = OpenSSL::Cipher::DES.new(:CBC)
        # get cipher
        decipher.decrypt
        decipher.key = @des_key
        decipher.iv = @iv

        payload = decipher.update(stream.value) + decipher.final
        OpenSSL::ASN1::Data.decode payload
      end

      private

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
