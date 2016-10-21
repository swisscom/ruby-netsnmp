RSpec.describe NETSNMP::Varbind do
  let(:struct) { double(:structure) }
  let(:pointer) { double(:pointer) }
  subject {  NETSNMP::Varbind.new(pointer) }
  before do
    allow(NETSNMP::Core::Structures::VariableList).to receive(:new).with(pointer).and_return(struct)
  end

  it { is_expected.to respond_to(:struct) }


  describe NETSNMP::RequestVarbind do
    subject {  NETSNMP::RequestVarbind.new(pdu, oid, value: value) }
    let(:p1) { double(:pdu_pointer) }
    let(:p2) { double(:oid_pointer) }
    let(:pdu) { double(:pdu, pointer: p1) }
    let(:oid) { double(:oid, pointer: p2, length: 2) }
    context "on initialization" do
      after { subject }
      context "when not passed type" do
        context "and the value is a fixnum" do
          let(:value) { 1 }
          it { expect(NETSNMP::Core::LibSNMP).to receive(:snmp_pdu_add_variable).with(p1, p2, 2, instance_of(Fixnum), instance_of(FFI::MemoryPointer), value.size).and_return(pointer) }
          # TODO: value.length is too abstract. but this value differs between 32 and 64 bit architectures...
        end
        context "and the value is a string" do
          let(:value) { "value" }
          it { expect(NETSNMP::Core::LibSNMP).to receive(:snmp_pdu_add_variable).with(p1, p2, 2, instance_of(Fixnum), value, 5).and_return(pointer) }
        end
        context "and the value is a oid" do
          let(:value) { NETSNMP::OID.new("SNMPv2-MIB::sysDescr.0") }
          let(:p3) { double(:value_pointer) }
          let(:len) { double(:length) }
          before do
            expect(value).to receive(:size).and_return(len)
            expect(value).to receive(:pointer).and_return(p3)
          end
          it { expect(NETSNMP::Core::LibSNMP).to receive(:snmp_pdu_add_variable).with(p1, p2, 2, instance_of(Fixnum), p3, len).and_return(pointer) }
        end
        context "and the value is nothing" do
          let(:value) { nil }
          it { expect(NETSNMP::Core::LibSNMP).to receive(:snmp_pdu_add_variable).with(p1, p2, 2, instance_of(Fixnum), nil, 0).and_return(pointer) }
        end

      end
    end
    describe "#to_ber" do
      it { expect(described_class.new(nil, ".1.3.6.1.2.1.1.1.0").to_ber).to eq("0\f\006\b+\006\001\002\001\001\001\000\005\000".b) }
    end
  end


  describe NETSNMP::ResponseVarbind do
    let(:value) { "value" }
    before { allow(subject).to receive(:load_varbind_value).and_return(value) }

  end
end
