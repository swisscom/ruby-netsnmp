# frozen_string_literal: true

module NETSNMP
  # This module encapsulates the public API for encrypting/decrypting and signing/verifying.
  #
  # It doesn't interact with other layers from the library, rather it is used and passed all
  # the arguments (consisting mostly of primitive types).
  # It also provides validation of the security options passed with a client is initialized in v3 mode.
  class SecurityParameters
    using StringExtensions
    using ASNExtensions

    include Loggable

    IPAD = "\x36" * 64
    OPAD = "\x5c" * 64

    # Timeliness is part of SNMP V3 Security
    # The topic is described very nice here https://www.snmpsharpnet.com/?page_id=28
    # https://www.ietf.org/rfc/rfc2574.txt 1.4.1 Timeliness
    # The probe is outdated after 150 seconds which results in a PDU Error, therefore it should expire before that and be renewed
    # The 150 Seconds is specified in https://www.ietf.org/rfc/rfc2574.txt 2.2.3
    TIMELINESS_THRESHOLD = 150

    attr_reader :security_level, :username, :auth_protocol, :engine_id

    # @param [String] username the snmp v3 username
    # @param [String] engine_id the device engine id (initialized to '' for report)
    # @param [Symbol, integer] security_level allowed snmp v3 security level (:auth_priv, :auth_no_priv, etc)
    # @param [Symbol, nil] auth_protocol a supported authentication protocol (currently supported: :md5, :sha, :sha256)
    # @param [Symbol, nil] priv_protocol a supported privacy protocol (currently supported: :des, :aes)
    # @param [String, nil] auth_password the authentication password
    # @param [String, nil] priv_password the privacy password
    #
    # @note if security level is set to :no_auth_no_priv, all other parameters are optional; if
    #   :auth_no_priv, :auth_protocol will be coerced to :md5 (if not explicitly set), and :auth_password is
    #   mandatory; if :auth_priv, the sentence before applies, and :priv_protocol will be coerced to :des (if
    #   not explicitly set), and :priv_password becomes mandatory.
    #
    def initialize(
      username:,
      engine_id: "",
      security_level: nil,
      auth_protocol: nil,
      auth_password: nil,
      priv_protocol: nil,
      priv_password: nil,
      **options
    )
      @security_level = case security_level
                        when /no_?auth/         then 0
                        when /auth_?no_?priv/   then 1
                        when /auth_?priv/       then 3
                        when Integer then security_level
                        else 3 # rubocop:disable Lint/DuplicateBranch
                        end
      @username = username
      @engine_id = engine_id
      @auth_protocol = auth_protocol.to_sym unless auth_protocol.nil?
      @priv_protocol = priv_protocol.to_sym unless priv_protocol.nil?

      if @security_level.positive?
        @auth_protocol ||= :md5 # this is the default
        raise "security level requires an auth password" if auth_password.nil?
        raise "auth password must have between 8 to 32 characters" unless (8..32).cover?(auth_password.length)
      end

      if @security_level > 1
        @priv_protocol ||= :des
        raise "security level requires a priv password" if priv_password.nil?
        raise "priv password must have between 8 to 32 characters" unless (8..32).cover?(priv_password.length)
      end

      @auth_pass_key = passkey(auth_password) if auth_password
      @priv_pass_key = passkey(priv_password) if priv_password
      initialize_logger(**options)
    end

    def engine_id=(id)
      @timeliness = Process.clock_gettime(Process::CLOCK_MONOTONIC, :second)
      @engine_id = id
    end

    # @param [#to_asn, #to_der] pdu the pdu to encode (must quack like a asn1 type)
    # @param [String] salt the salt to use
    # @param [Integer] engine_time the reported engine time
    # @param [Integer] engine_boots the reported boots time
    #
    # @return [Array] a pair, where the first argument in the asn structure with the encoded pdu,
    #    and the second is the calculated salt (if it has been encrypted)
    def encode(pdu, salt:, engine_time:, engine_boots:)
      encryptor = encryption

      if encryptor
        encrypted_pdu, salt = encryptor.encrypt(pdu.to_der, engine_boots: engine_boots,
                                                            engine_time: engine_time)
        [
          OpenSSL::ASN1::OctetString.new(encrypted_pdu).with_label(:encrypted_pdu),
          OpenSSL::ASN1::OctetString.new(salt).with_label(:salt)
        ]
      else
        [pdu.to_asn, salt]
      end
    end

    # @param [String] der the encoded der to be decoded
    # @param [String] salt the salt from the incoming der
    # @param [Integer] engine_time the reported engine time
    # @param [Integer] engine_boots the reported engine boots
    def decode(der, salt:, engine_time:, engine_boots:, security_level: @security_level)
      asn = OpenSSL::ASN1.decode(der)
      return asn if security_level < 3

      encryptor = encryption
      return asn unless encryptor

      encrypted_pdu = asn.value
      pdu_der = encryptor.decrypt(encrypted_pdu, salt: salt, engine_time: engine_time, engine_boots: engine_boots)
      log(level: 2) { "message has been decrypted" }
      OpenSSL::ASN1.decode(pdu_der)
    end

    # @param [String] message the already encoded snmp v3 message
    # @return [String] the digest signature of the message payload
    #
    # @note this method is used in the process of authenticating a message
    def sign(message)
      # don't sign unless you have to
      return unless @auth_protocol

      key = auth_key.dup

      # SHA256 => https://datatracker.ietf.org/doc/html/rfc7860#section-4.2.2
      # The 24 first octets of HMAC are taken as the computed MAC value
      return OpenSSL::HMAC.digest("SHA256", key, message)[0, 24] if @auth_protocol == :sha256

      # MD5 => https://datatracker.ietf.org/doc/html/rfc3414#section-6.3.2
      # SHA1 => https://datatracker.ietf.org/doc/html/rfc3414#section-7.3.2
      key << ("\x00" * (@auth_protocol == :md5 ? 48 : 44))
      k1 = key.xor(IPAD)
      k2 = key.xor(OPAD)

      digest.reset
      digest << (k1 + message)
      d1 = digest.digest

      digest.reset
      digest << (k2 + d1)
      # The 12 first octets of the digest are taken as the computed MAC value
      digest.digest[0, 12]
    end

    # @param [String] stream the encoded incoming payload
    # @param [String] salt the incoming payload''s salt
    #
    # @raise [NETSNMP::Error] if the message's integration has been violated
    def verify(stream, salt, security_level: @security_level)
      return if security_level.nil? || security_level < 1

      verisalt = sign(stream)
      raise Error, "invalid message authentication salt" unless verisalt == salt

      log(level: 2) { "message has been verified" }
    end

    def must_revalidate?
      return @engine_id.empty? unless authorizable?
      return true if @engine_id.empty? || @timeliness.nil?

      (Process.clock_gettime(Process::CLOCK_MONOTONIC, :second) - @timeliness) >= TIMELINESS_THRESHOLD
    end

    private

    def auth_key
      @auth_key ||= localize_key(@auth_pass_key)
    end

    def priv_key
      @priv_key ||= localize_key(@priv_pass_key)
    end

    def localize_key(key)
      digest.reset
      digest << key
      digest << @engine_id
      digest << key

      digest.digest
    end

    def passkey(password)
      digest.reset
      digest << expand_passphrase(password)

      dig = digest.digest
      dig = dig[0, 16] if @auth_protocol == :md5
      dig || ""
    end

    def expand_passphrase(password)
      password_index = 0
      buffer = "".b
      password_length = password.length
      while password_index < 1048576
        initial = password_index % password_length
        rotated = String(password.byteslice(initial..-1)) + String(password.byteslice(0, initial))
        buffer << (rotated * (64 / rotated.length)) + String(rotated.byteslice(0, 64 % rotated.length))
        password_index += 64
      end
      buffer
    end

    def digest
      @digest ||= case @auth_protocol
                  when :md5 then OpenSSL::Digest.new("MD5")
                  when :sha then OpenSSL::Digest.new("SHA1")
                  when :sha256 then OpenSSL::Digest.new("SHA256")
                  else
                    raise Error, "unsupported auth protocol: #{@auth_protocol}"
                  end
    end

    def encryption
      @encryption ||= case @priv_protocol
                      when :des then Encryption::DES.new(priv_key)
                      when :aes then Encryption::AES.new(priv_key)
                      end
    end

    def authorizable?
      @auth_protocol != :none
    end
  end
end
