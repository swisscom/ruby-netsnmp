# FROM https://tools.ietf.org/html/rfc3414#appendix-A.2.1
RSpec.describe NETSNMP::Authentication::MD5 do
  subject { described_class.new("maplesyrup", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02".b) }
  describe "#passkey" do
    it { expect(subject.send(:passkey).b).to eq("\x9f\xaf\x32\x83\x88\x4e\x92\x83\x4e\xbc\x98\x47\xd8\xed\xd9\x63".b) }
    it { expect(subject.localized_key).to eq("\x52\x6f\x5e\xed\x9f\xcc\xe2\x6f\x89\x64\xc2\x93\x07\x87\xd8\x2b".b) }
  end
end
