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
    it do
      expect(md5_sec.send(:auth_key)).to eq("\x52\x6f\x5e\xed\x9f\xcc\xe2\x6f\x89\x64\xc2\x93\x07\x87\xd8\x2b".b)
      expect(md5_sec.send(:priv_key)).to eq("\x52\x6f\x5e\xed\x9f\xcc\xe2\x6f\x89\x64\xc2\x93\x07\x87\xd8\x2b".b)
      expect(sha_sec.send(:auth_key)).to eq("\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f".b)
      expect(sha_sec.send(:priv_key)).to eq("\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f".b)
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
