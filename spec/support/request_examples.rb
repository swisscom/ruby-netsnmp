RSpec.shared_examples "an snmp client" do
  let(:host) { "localhost" }
  let(:device_options) { {
    peername: "localhost",
    port: SNMPPORT
  } }
  let(:protocol_options) { { } } 
  let(:extra_options) { { } }
  let(:options) { protocol_options.merge(device_options).merge(extra_options) }

  subject { described_class.new(host, options) }

  describe "#get" do
    let(:value) { subject.get(oid: get_oid) }
    it "fetches the varbinds for a given oid" do
      expect(value).to eq(get_result)
    end
  end

  describe "#get_next" do
    let(:varbind) { subject.get_next(oid: get_oid) }
    it "fetches the varbinds for the next oid" do
      oid, value = varbind
      expect(value).to start_with(next_result)
      expect(oid).to eq(next_oid)
    end
  end

  describe "#walk" do
    let(:value) { subject.walk(walk_oid) }
    it "fetches the varbinds for the next oid" do
      expect(value.map {|oid, val| "#{oid}: #{val}" }.join("\n") << "\n").to eq(walk_result)
#      expect(value.next).to eq(["#{oid}.1","The SNMP Management Architecture MIB."])
#      expect(value.next).to eq(["#{oid}.2","The MIB for Message Processing and Dispatching."])
#      expect(value.next).to eq(["#{oid}.3","The management information definitions for the SNMP User-based Security Model."])
#      expect(value.next).to eq(["#{oid}.4","The MIB module for SNMPv2 entities"])
#      expect(value.next).to eq(["#{oid}.5","The MIB module for managing TCP implementations"])
#      expect(value.next).to eq(["#{oid}.6","The MIB module for managing IP and ICMP implementations"])
#      expect(value.next).to eq(["#{oid}.7","The MIB module for managing UDP implementations"])
#      expect(value.next).to eq(["#{oid}.8","View-based Access Control Model for SNMP."])
#      expect{ value.next }.to raise_error(StopIteration)
    end
  end

#  describe "#get_bulk" do
#    let(:oid) { "1.3.6.1.2.1.1.9.1.3" }
#    let(:value) { subject.get_bulk(oid: oid) }
#    it "fetches the varbinds for the next oid" do
#      expect(value.next).to eq(["#{oid}.1","The SNMP Management Architecture MIB."])
#      expect(value.next).to eq(["#{oid}.2","The MIB for Message Processing and Dispatching."])
#      expect(value.next).to eq(["#{oid}.3","The management information definitions for the SNMP User-based Security Model."])
#      expect(value.next).to eq(["#{oid}.4","The MIB module for SNMPv2 entities"])
#      expect(value.next).to eq(["#{oid}.5","The MIB module for managing TCP implementations"])
#      expect(value.next).to eq(["#{oid}.6","The MIB module for managing IP and ICMP implementations"])
#      expect(value.next).to eq(["#{oid}.7","The MIB module for managing UDP implementations"])
#      expect(value.next).to eq(["#{oid}.8","View-based Access Control Model for SNMP."])
#      expect(value.next).to eq(["1.3.6.1.2.1.1.9.1.4.1",2])
#      expect(value.next).to eq(["1.3.6.1.2.1.1.9.1.4.2",2])
#      expect{ value.next }.to raise_error(StopIteration)
#    end
#  end

 
  # TODO: use this oid to test error calls
  #  let(:oid) { "SNMPv2-MIB::sysORDescr.1" }

#  describe "#set" do
#    let(:oid) { "1.3.6.1.2.1.1.3.0" } # sysUpTimeInstance
#    let(:extra_options) { { community: "variation/notification" } }
#    after { subject.set(set_oid, value: set_oid_result, type: :timetick ) } 
#    it "updates the value of the oid" do
#      expect(subject.get(set_oid)).to eq(set_oid_result)
#  
#      # without type
#      subject.set(oid, value: "SNMP2TEST" )
#      expect(subject.get(set_oid)).to eq("SNMP2TEST")
#
#    end
#  end

end
