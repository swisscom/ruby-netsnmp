# frozen_string_literal: true

module NETSNMP
  module Encryption
    # https://www.rfc-editor.org/rfc/rfc3826
    # https://snmp.com/snmpv3/snmpv3_aes256.shtml
    # Note: AES Blumental is not supported and not widely used
    class AES
      def initialize(priv_key, cipher: , local: 0)
        @priv_key = priv_key
        @local = local
        @cipher = cipher
      end

      def encrypt(decrypted_data, engine_boots:, engine_time:)
        cipher = case @cipher
        when :aes, :aes128 then OpenSSL::Cipher.new("aes-128-cfb")
        when :aes192 then OpenSSL::Cipher.new("aes-192-cfb")
        when :aes256 then OpenSSL::Cipher.new("aes-256-cfb")
        end

        iv, salt = generate_encryption_key(engine_boots, engine_time)

        cipher.encrypt
        cipher.iv = case @cipher
        when :aes, :aes128 then iv[0, 16]
        when :aes192 then iv[0, 24]
        when :aes256 then iv[0, 32]
        end
        cipher.key = aes_key

        if (diff = decrypted_data.length % 8) != 0
          decrypted_data << ("\x00" * (8 - diff))
        end

        encrypted_data = cipher.update(decrypted_data) + cipher.final

        [encrypted_data, salt]
      end

      def decrypt(encrypted_data, salt:, engine_boots:, engine_time:)
        raise Error, "invalid priv salt received" unless !salt.empty? && (salt.length % 8).zero?

        cipher = case @cipher
        when :aes, :aes128 then OpenSSL::Cipher.new("aes-128-cfb")
        when :aes192 then OpenSSL::Cipher.new("aes-192-cfb")
        when :aes256 then OpenSSL::Cipher.new("aes-256-cfb")
        end
        cipher.padding = 0

        iv = generate_decryption_key(engine_boots, engine_time, salt)

        cipher.decrypt
        cipher.key = aes_key
        cipher.iv = case @cipher
        when :aes, :aes128 then iv[0..16]
        when :aes192 then iv[0..24]
        when :aes256 then iv[0..32]
        end
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
        iv = case @cipher
        when :aes, :aes128 then iv[0, 16]
        when :aes192 then iv[0, 24]
        when :aes256 then iv[0, 32]
        end

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
        case @cipher
        when :aes, :aes128 then @priv_key[0, 16]
        when :aes192 then @priv_key[0, 24]
        when :aes256 then @priv_key[0, 32]
        end
      end
    end
  end
end
