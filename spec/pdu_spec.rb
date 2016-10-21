RSpec.describe NETSNMP::PDU do
  let(:struct) { double(:structure) }
  let(:pointer) { double(:pointer) }
  subject {  NETSNMP::PDU.new(pointer) }
  before do
    allow(NETSNMP::Core::Structures::PDU).to receive(:new).with(pointer).and_return(struct)
  end

  it { is_expected.to respond_to(:struct) }
  it { expect(subject.varbinds).to be_empty }

  describe NETSNMP::RequestPDU do
    before { allow(NETSNMP::Core::LibSNMP).to receive(:snmp_pdu_create).and_return(pointer) }
    subject { NETSNMP::PDU.build(:get) }
  end





  describe "#to_ber" do
    let(:encoded_get_request) { "0'\002\001\000\004\006public\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000" }
    context "v2c" do
      subject { described_class.build(:get, 
                                        version: 0,
                                        request_id: 16170,
                                        community: "public") }
      let(:struct) { double(:structure) }
      before { allow(NETSNMP::Core::LibSNMP).to receive(:snmp_pdu_create).and_return(pointer) }
      before do
     $result = encoded_get_request.b
        subject.add_varbind(".1.3.6.1.2.1.1.1.0")
      end
      it { expect(subject.to_ber).to eq(encoded_get_request.b) }
    end

  end
end
