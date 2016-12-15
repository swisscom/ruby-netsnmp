module NETSNMP
  module Encryption
    class DES
      def initialize(priv_key, local: 0)
        @priv_key = priv_key
        @local = local
      end


      def encrypt(decrypted_data, engine_boots: , engine_time: nil)
        cipher = OpenSSL::Cipher::DES.new(:CBC)

        iv, salt = generate_encryption_key(engine_boots)

        cipher.encrypt
        cipher.iv = iv
        cipher.key = des_key

        if (diff = decrypted_data.length % 8) != 0
          decrypted_data << ("\x00" * (8 - diff))
        end

        encrypted_data = cipher.update(decrypted_data) + cipher.final
        [encrypted_data, salt]
      end

      def decrypt(encrypted_data, salt: , engine_boots: nil, engine_time: nil)
        # TODO: error out if salt length != 8
        # TODO: error out if encrypted data size % 8 != 0

        cipher = OpenSSL::Cipher::DES.new(:CBC)
        cipher.padding = 0

        iv = generate_decryption_key(salt)

        cipher.decrypt
        cipher.key = des_key
        cipher.iv = iv
        decrypted_data = cipher.update(encrypted_data) + cipher.final
        # chomp padded nulls
        # TODO: I don't know, but what if the last value is null?
        decrypted_data.slice!(/\0*\Z/)
        decrypted_data
      end


      private
      # 8.1.1.1
      def generate_encryption_key(boots)
        pre_iv = @priv_key[8,8]
        salt = [0xff & (boots >> 24),
                0xff & (boots >> 16),
                0xff & (boots >> 8),
                0xff &  boots,
                0xff & (@local >> 24),
                0xff & (@local >> 16),
                0xff & (@local >> 8),
                0xff &  @local].pack("c*")
         @local = @local == 0xffffffff ? 0 : @local + 1

         iv = pre_iv.xor(salt)
         [iv, salt]
       end

       def generate_decryption_key(salt)
         pre_iv = @priv_key[8,8]
         pre_iv.xor(salt)
       end

      def des_key 
        @priv_key[0,8]
      end
    end
  end
end
