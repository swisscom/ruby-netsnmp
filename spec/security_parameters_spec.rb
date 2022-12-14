# frozen_string_literal: true

# FROM https://tools.ietf.org/html/rfc3414#appendix-A.2.1
RSpec.describe NETSNMP::SecurityParameters do
  let(:engine_id) { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02".b }
  let(:password) { "maplesyrup" }
  describe "#passkey" do
    context "md5" do
      subject { described_class.new(security_level: :auth_no_priv, auth_protocol: :md5, username: "username", engine_id: engine_id, auth_password: "maplesyrup") }
      it { expect(subject.send(:passkey, password)).to eq("\x9f\xaf\x32\x83\x88\x4e\x92\x83\x4e\xbc\x98\x47\xd8\xed\xd9\x63".b) }
    end
    context "sha" do
      subject { described_class.new(security_level: :auth_priv, auth_protocol: :sha, username: "username", engine_id: engine_id, auth_password: "maplesyrup", priv_password: "maplesyrup") }
      it { expect(subject.send(:passkey, password).b).to eq("\x9f\xb5\xcc\x03\x81\x49\x7b\x37\x93\x52\x89\x39\xff\x78\x8d\x5d\x79\x14\x52\x11".b) }
    end
    context "sha224" do
      subject do
        described_class.new(security_level: :auth_priv, auth_protocol: :sha224, username: "username", engine_id: engine_id, auth_password: "maplesyrup", priv_password: "maplesyrup")
      end

      it { expect(subject.send(:passkey, password).b).to eq("(*Xg\xEE\x9A\xACc\x9A\xD5\x9D\xF9W,}:\xC0\xFB\xC1:\x90[m\xF0}\xBB\xF0\v".b) }
    end
    context "sha256" do
      subject do
        described_class.new(security_level: :auth_priv, auth_protocol: :sha256, username: "username", engine_id: engine_id, auth_password: "maplesyrup", priv_password: "maplesyrup")
      end

      it { expect(subject.send(:passkey, password).b).to eq("\xABQ\x01M\x1E\a\x7F`\x17\xDF+\x12\xBE\xE5\xF5\xAAr\x991w\xE9\xBBV\x9CM\xFFZL\xA0\xB4\xAF\xAC".b) }
    end
    context "sha384" do
      subject do
        described_class.new(security_level: :auth_priv, auth_protocol: :sha384, username: "username", engine_id: engine_id, auth_password: "maplesyrup", priv_password: "maplesyrup")
      end

      it { expect(subject.send(:passkey, password).b).to eq("\xE0n\xCC\xDF,h\xA0n\xD04r<\x9C&\xE0\xDB;f\x9E\x1E.\xFE\xD4\x91P\xB5Sw\xA2\xE9\x8F8<\x86\xFB\x83hWDFT\xB2\x87\xC9?Q\xFFd".b) }
    end
    context "sha512" do
      subject do
        described_class.new(security_level: :auth_priv, auth_protocol: :sha512, username: "username", engine_id: engine_id, auth_password: "maplesyrup", priv_password: "maplesyrup")
      end

      it { expect(subject.send(:passkey, password).b).to eq("~C\x96\xDEZ\xAD\xC7{\xE8S\x81\x9B\x98\xC9@be\xB3\xA9\xC3|\xC3\x17ei\x84zNOo\xBAc\xDD:s\xD0I$\xD3\x1Ac\xF9Z`\x1F\x93\x85\xAFk\xE4\xED\e7\xF8}\x04\x0F|n\xD6\xF8\xD3\x8A\x91".b) }
    end
  end

  describe "keys" do
    let(:md5_sec) do
      described_class.new(security_level: :auth_priv,
                          auth_protocol: :md5,
                          priv_protocol: :des,
                          username: "username",
                          auth_password: password,
                          priv_password: password,
                          engine_id: engine_id)
    end
    let(:sha_sec) do
      described_class.new(security_level: :auth_priv,
                          auth_protocol: :sha,
                          priv_protocol: :des,
                          username: "username",
                          auth_password: password,
                          priv_password: password,
                          engine_id: engine_id)
    end
    let(:sha224_sec) do
      described_class.new(security_level: :auth_priv,
                          auth_protocol: :sha224,
                          priv_protocol: :des,
                          username: "username",
                          auth_password: password,
                          priv_password: password,
                          engine_id: engine_id)
    end
    let(:sha256_sec) do
      described_class.new(security_level: :auth_priv,
                          auth_protocol: :sha256,
                          priv_protocol: :des,
                          username: "username",
                          auth_password: password,
                          priv_password: password,
                          engine_id: engine_id)
    end
    let(:sha384_sec) do
      described_class.new(security_level: :auth_priv,
                          auth_protocol: :sha384,
                          priv_protocol: :des,
                          username: "username",
                          auth_password: password,
                          priv_password: password,
                          engine_id: engine_id)
    end
    let(:sha512_sec) do
      described_class.new(security_level: :auth_priv,
                          auth_protocol: :sha512,
                          priv_protocol: :des,
                          username: "username",
                          auth_password: password,
                          priv_password: password,
                          engine_id: engine_id)
    end
    it do
      expect(md5_sec.send(:auth_key)).to eq("\x52\x6f\x5e\xed\x9f\xcc\xe2\x6f\x89\x64\xc2\x93\x07\x87\xd8\x2b".b)
      expect(md5_sec.send(:priv_key)).to eq("\x52\x6f\x5e\xed\x9f\xcc\xe2\x6f\x89\x64\xc2\x93\x07\x87\xd8\x2b".b)
      expect(sha_sec.send(:auth_key)).to eq("\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f".b)
      expect(sha_sec.send(:priv_key)).to eq("\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f".b)
      expect(sha224_sec.send(:auth_key)).to eq("\v\xD8\x82|n)\xF8\x06^\b\xE0\x927\xF1w\xE4\x10\xF6\x9B\x90\xE1x+\xE6\x82\aVt".b)
      expect(sha224_sec.send(:priv_key)).to eq("\v\xD8\x82|n)\xF8\x06^\b\xE0\x927\xF1w\xE4\x10\xF6\x9B\x90\xE1x+\xE6\x82\aVt".b)
      expect(sha256_sec.send(:auth_key)).to eq("\x89\x82\xE0\xE5I\xE8f\xDB6\x1Akb]\x84\xCC\xCC\x11\x16-E>\xE8\xCE:dE\xC2\xD6wo\x0F\x8B".b)
      expect(sha256_sec.send(:priv_key)).to eq("\x89\x82\xE0\xE5I\xE8f\xDB6\x1Akb]\x84\xCC\xCC\x11\x16-E>\xE8\xCE:dE\xC2\xD6wo\x0F\x8B".b)
      expect(sha384_sec.send(:auth_key)).to eq(";)\x8F\x16\x16J\x11\x18By\xD5C+\xF1i\xE2\xD2\xA4\x83\a\xDE\x02\xB3\xD3\xF7\xE2\xB4\xF3n\xB6\xF0EZSh\x9A97\xEE\xA0s\x19\xA63\xD2\xCC\xBAx".b)
      expect(sha384_sec.send(:priv_key)).to eq(";)\x8F\x16\x16J\x11\x18By\xD5C+\xF1i\xE2\xD2\xA4\x83\a\xDE\x02\xB3\xD3\xF7\xE2\xB4\xF3n\xB6\xF0EZSh\x9A97\xEE\xA0s\x19\xA63\xD2\xCC\xBAx".b)
      expect(sha512_sec.send(:auth_key)).to eq("\"\xA5\xA3l\xED\xFC\xC0\x85\x80z\x12\x8D{\xC6\xC28!g\xADl\r\xBC_\xDF\xF8Vt\x0F=\x84\xC0\x99\xAD\x1E\xA8z\x8D\xB0\x96qM\x97\x88\xBDT@G\xC9\x02\x1EB)\xCE'\xE4\xC0\xA6\x92P\xAD\xFC\xFF\xBB\v".b)
      expect(sha512_sec.send(:priv_key)).to eq("\"\xA5\xA3l\xED\xFC\xC0\x85\x80z\x12\x8D{\xC6\xC28!g\xADl\r\xBC_\xDF\xF8Vt\x0F=\x84\xC0\x99\xAD\x1E\xA8z\x8D\xB0\x96qM\x97\x88\xBDT@G\xC9\x02\x1EB)\xCE'\xE4\xC0\xA6\x92P\xAD\xFC\xFF\xBB\v".b)

    end
  end

  context "#must_revalidate?" do
    let(:security_options) do
      { username: "authprivmd5des", auth_password: "maplesyrup",
        auth_protocol: :md5, priv_password: "maplesyrup",
        priv_protocol: :des, security_level: :auth_priv }
    end
    subject { described_class.new(**security_options) }
    context "for v3" do
      context "when initialized" do
        it { expect(subject.must_revalidate?).to be_truthy }
      end
      context "when given a new engine id" do
        before { subject.engine_id = "NEWENGINE" }
        it { expect(subject.must_revalidate?).to be_falsy }
        context "when limit surpasses" do
          before do
            subject.instance_variable_set(:@timeliness, Process.clock_gettime(Process::CLOCK_MONOTONIC, :second) - 150)
          end
          it { expect(subject.must_revalidate?).to be_truthy }
          context "when given a new engine id" do
            before { subject.engine_id = "UPDATEDENGINE" }
            it { expect(subject.must_revalidate?).to be_falsy }
          end
        end
      end
    end
  end
end
