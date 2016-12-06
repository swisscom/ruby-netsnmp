# FROM https://tools.ietf.org/html/rfc3414#appendix-A.2.1
RSpec.describe NETSNMP::Authentication::MD5 do
  describe "#passkey" do
    subject { described_class.new("maplesyrup") }
    it { expect(subject.send(:passkey).b).to eq("\x9f\xaf\x32\x83\x88\x4e\x92\x83\x4e\xbc\x98\x47\xd8\xed\xd9\x63".b) }
  end
 

  describe "#generate_key" do
    let(:engineid) { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02".b }
    subject { described_class.new("maplesyrup") }
    it { expect(subject.send(:generate_key, engineid).b).to eq("\x52\x6f\x5e\xed\x9f\xcc\xe2\x6f\x89\x64\xc2\x93\x07\x87\xd8\x2b".b) } 
  end 
end
