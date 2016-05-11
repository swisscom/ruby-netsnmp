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

    describe "#add_varbind" do
      let(:oid) { double(:oid) }
      let(:value) { double(:value) }
      let(:varbind) { double(:varbind) }
      before { allow(NETSNMP::RequestVarbind).to receive(:new).with(subject, oid, value, instance_of(Hash)).and_return(varbind) }
      it "creates a new varbind and adds it to the structure" do
        subject.add_varbind(oid, { value: value }) 
        expect(subject.varbinds).not_to be_empty
        expect(subject.varbinds).to include(varbind) 
      end
    end
  end

end
