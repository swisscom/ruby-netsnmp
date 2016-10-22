RSpec.shared_examples "an snmp client" do
  let(:host) { "localhost" }
  let(:device_options) { {
    peername: "localhost",
    port: SNMPPORT
  } }
  let(:protocol_options) { { } } 
  let(:options) { protocol_options.merge(device_options) }

  subject { puts options; described_class.new(host, options) }

  describe "#get" do
    let(:oid) { "1.3.6.1.2.1.1.5.0" } # sysName.0
    let(:value) { subject.get(oid) }
    it "fetches the varbinds for a given oid" do
      expect(value).to eq(sysname)
    end
  end

  describe "#get_next" do
    let(:oid) { "1.3.6.1.2.1.1.5.0" } # sysName.0
    let(:value) { subject.get_next(oid) }
    it "fetches the varbinds for the next oid" do
      expect(value).to start_with("KK12")
    end
  end

  describe "#walk" do
    let(:oid) { "1.3.6.1.2.1.1.9.1.3" } # sysORDescr
    let(:value) { subject.walk(oid) }
    it "fetches the varbinds for the next oid" do
      expect(value.next).to eq(["#{oid}.1","The SNMP Management Architecture MIB."])
      expect(value.next).to eq(["#{oid}.2","The MIB for Message Processing and Dispatching."])
      expect(value.next).to eq(["#{oid}.3","The management information definitions for the SNMP User-based Security Model."])
      expect(value.next).to eq(["#{oid}.4","The MIB module for SNMPv2 entities"])
      expect(value.next).to eq(["#{oid}.5","The MIB module for managing TCP implementations"])
      expect(value.next).to eq(["#{oid}.6","The MIB module for managing IP and ICMP implementations"])
      expect(value.next).to eq(["#{oid}.7","The MIB module for managing UDP implementations"])
      expect(value.next).to eq(["#{oid}.8","View-based Access Control Model for SNMP."])
      expect{ value.next }.to raise_error(StopIteration)
    end
  end

  describe "#get_bulk" do
    let(:oid) { "1.3.6.1.2.1.1.9.1.3" }
    let(:value) { subject.get_bulk(oid) }
    it "fetches the varbinds for the next oid" do
      expect(value.next).to eq(["#{oid}.1","The SNMP Management Architecture MIB."])
      expect(value.next).to eq(["#{oid}.2","The MIB for Message Processing and Dispatching."])
      expect(value.next).to eq(["#{oid}.3","The management information definitions for the SNMP User-based Security Model."])
      expect(value.next).to eq(["#{oid}.4","The MIB module for SNMPv2 entities"])
      expect(value.next).to eq(["#{oid}.5","The MIB module for managing TCP implementations"])
      expect(value.next).to eq(["#{oid}.6","The MIB module for managing IP and ICMP implementations"])
      expect(value.next).to eq(["#{oid}.7","The MIB module for managing UDP implementations"])
      expect(value.next).to eq(["#{oid}.8","View-based Access Control Model for SNMP."])
      expect(value.next).to eq(["1.3.6.1.2.1.1.9.1.4.1",2])
      expect(value.next).to eq(["1.3.6.1.2.1.1.9.1.4.2",2])
      expect{ value.next }.to raise_error(StopIteration)
    end
  end

 
  # TODO: use this oid to test error calls
  #  let(:oid) { "SNMPv2-MIB::sysORDescr.1" }

  describe "#set" do
    let(:oid) { "1.3.6.1.2.1.1.3.0" } # sysUpTimeInstance
    let(:new_value) { 43 }
    after { subject.set(oid, value: 42) }
    it "updates the value of the oid" do
      expect(subject.get(oid)).to be(42)
  
      # without type
      subject.set(oid, value: 43)
      expect(subject.get(oid)).to be(43)

      subject.set(oid, value: 44, type: :integer)
      expect(subject.get(oid)).to be(44)

    end
  end

end
