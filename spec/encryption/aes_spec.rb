
RSpec.describe NETSNMP::Encryption::AES do
  subject { described_class.new(secret_key) }
  let(:data_to_encrypt) { "C\b19710917" }
  let(:encrypted_data) { "\t\xC0\xD2\x1FD\x85\x16;\x8D\x84D!\x04\xA1O\x9E" }
  let(:salt) { "\x00\x00\x00\x00\x00\x00\x00\x00" }
  let(:secret_key) { "1234567890abcdef" }

  describe "#encrypt" do
    specify "the encryption is correct" do
      enc_data, enc_salt = subject.encrypt(data_to_encrypt, engine_boots: 1, engine_time: 1)
      expect(enc_data.bytes).to eq(encrypted_data.bytes)
      expect(enc_salt.bytes).to eq(salt.bytes)
    end
  end

  describe "#decrypt" do
    specify "the decryption is correct" do
      decryption = subject.decrypt(encrypted_data, salt: salt, engine_boots: 1, engine_time: 1)
      expect(decryption).to eq(data_to_encrypt)
    end
  end
end
