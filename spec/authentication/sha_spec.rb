# FROM https://tools.ietf.org/html/rfc3414#appendix-A.2.2
RSpec.describe NETSNMP::Authentication::SHA do
  describe "#passkey" do
    subject { described_class.new("maplesyrup") }
    it { expect(subject.send(:passkey).b).to eq("\x9f\xb5\xcc\x03\x81\x49\x7b\x37\x93\x52\x89\x39\xff\x78\x8d\x5d\x79\x14\x52\x11".b) }
  end
 

  describe "#generate_key" do
    let(:engineid) { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02".b }
    subject { described_class.new("maplesyrup") }
    it { expect(subject.send(:generate_key, engineid).b).to eq("\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f".b) } 
  end 
end
