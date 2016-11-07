module NETSNMP
  module Encryption
    class DES < None
      SALTLSB = Random.new.bytes(4)

      def initialize(password, engineboots)
        super
        prev_iv = password[4,4]
      end

      def initialize(password, engineboots)
        super
        @des_key = generate_key(password)
        @iv = generate_iv(password, engineboots)
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
        raise unless seq.size % 8 == 0

        decipher = OpenSSL::Cipher::DES.new(:CBC)
        # get cipher
        decipher.decrypt
        decipher.key = @des_key
        decipher.iv = @iv

        payload = decipher.update(stream.value) + decipher.final
        OpenSSL::ASN1::Data.decode payload
      end

      private


      # https://tools.ietf.org/html/rfc3414#section-8.1.1.1
      #
      #
      def generate_iv(password, engineboots)
        prev_iv = password[4, 4]

   
        # make this 32 bit
        boots_str = [engineboots.to_s].pack("H*")
        boots_str.prepend("\x00") while boots_str.size < 4

        # concat 32 bit engine boot with local32 bit integer
        @salt = boots_str[0,4].concat(SALTLSB)
        prev_iv.xor(salt)
      end

      # ihttps://tools.ietf.org/html/rfc3414#section-8.1.1.1
      #
      # The first 8 octets of the 16-octet secret (private privacy key) are
      # used as a DES key.  Since DES uses only 56 bits, the Least
      # Significant Bit in each octet is disregarded.
      #
      def generate_key(password)
        # get first 8 octets of password
        passstream = to_octets(password)[0, 64]
        (1..8).reverse_each do |least_significant|
          passstream.delete_at(least_significant * 8 - 1)
        end
        des_key = [passstream.join].pack("B*") # 56 bits
        des_key.prepend("\x00") # key must be 64 bits, or openssl won't accept it
        des_key 
      end

      def to_octets(word)
         word.unpack("B*").flat_map(&:chars)
      end
    end
  end
end
