# frozen_string_literal: true

module NETSNMP
  module Encryption
    class AES
      def initialize(priv_key, local: 0)
        @priv_key = priv_key
        @local = local
      end

      def encrypt(decrypted_data, engine_boots:, engine_time:)
        cipher = OpenSSL::Cipher::AES128.new(:CFB)

        iv, salt = generate_encryption_key(engine_boots, engine_time)

        cipher.encrypt
        cipher.iv = iv
        cipher.key = aes_key

        if (diff = decrypted_data.length % 8) != 0
          decrypted_data << ("\x00" * (8 - diff))
        end

        encrypted_data = cipher.update(decrypted_data) + cipher.final

        [encrypted_data, salt]
      end

      def decrypt(encrypted_data, salt:, engine_boots:, engine_time:)
        raise Error, "invalid priv salt received" unless !salt.empty? && (salt.length % 8).zero?

        cipher = OpenSSL::Cipher::AES128.new(:CFB)
        cipher.padding = 0

        iv = generate_decryption_key(engine_boots, engine_time, salt)

        cipher.decrypt
        cipher.key = aes_key
        cipher.iv = iv
        decrypted_data = cipher.update(encrypted_data) + cipher.final

        hlen, bodylen = OpenSSL::ASN1.traverse(decrypted_data) { |_, _, x, y, *| break x, y }
        decrypted_data.byteslice(0, hlen + bodylen) || "".b
      end

      private

      # 8.1.1.1
      def generate_encryption_key(boots, time)
        salt = [0xff & (@local >> 56),
                0xff & (@local >> 48),
                0xff & (@local >> 40),
                0xff & (@local >> 32),
                0xff & (@local >> 24),
                0xff & (@local >> 16),
                0xff & (@local >> 8),
                0xff &  @local].pack("c*")
        @local = @local == 0xffffffffffffffff ? 0 : @local + 1

        iv = generate_decryption_key(boots, time, salt)

        [iv, salt]
      end

      def generate_decryption_key(boots, time, salt)
        [0xff & (boots >> 24),
         0xff & (boots >> 16),
         0xff & (boots >> 8),
         0xff &  boots,
         0xff & (time >> 24),
         0xff & (time >> 16),
         0xff & (time >> 8),
         0xff &  time].pack("c*") + salt
      end

      def aes_key
        @priv_key[0, 16]
      end
    end
  end
end
