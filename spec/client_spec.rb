RSpec.describe NETSNMP::Client do
  let(:host) { "localhost" }
  let(:host_options) { {
    peername: "localhost",
    port: SNMPPORT,
    username: "simulator",
    auth_password: "auctoritas",
    auth_protocol: :md5,
    priv_password: "privatus",
    priv_protocol: :des
  } }

  subject { described_class.new(host, options) }

  describe "#get" do
    let(:oid) { "sysName.0" }
    let(:value) { subject.get(oid) }
    let(:options) { host_options.merge(context: "a172334d7d97871b72241397f713fa12") }
    it "fetches the varbinds for a given oid" do
      expect(value).to eq("tt")
    end
  end

  describe "#get_next" do
    let(:oid) { "sysName.0" }
    let(:value) { subject.get_next(oid) }
    let(:options) { host_options.merge(context: "a172334d7d97871b72241397f713fa12") }
    it "fetches the varbinds for the next oid" do
      expect(value).to start_with("KK12")
    end
  end

  describe "#walk" do
    let(:oid) { "sysORDescr" }
    let(:oid_code) { "1.3.6.1.2.1.1.9.1.3" }
    let(:value) { subject.walk(oid) }
    let(:options) { host_options.merge(context: "a172334d7d97871b72241397f713fa12") }
    it "fetches the varbinds for the next oid" do
      expect(value.next).to eq(["#{oid_code}.1","The SNMP Management Architecture MIB."])
      expect(value.next).to eq(["#{oid_code}.2","The MIB for Message Processing and Dispatching."])
      expect(value.next).to eq(["#{oid_code}.3","The management information definitions for the SNMP User-based Security Model."])
      expect(value.next).to eq(["#{oid_code}.4","The MIB module for SNMPv2 entities"])
      expect(value.next).to eq(["#{oid_code}.5","The MIB module for managing TCP implementations"])
      expect(value.next).to eq(["#{oid_code}.6","The MIB module for managing IP and ICMP implementations"])
      expect(value.next).to eq(["#{oid_code}.7","The MIB module for managing UDP implementations"])
      expect(value.next).to eq(["#{oid_code}.8","View-based Access Control Model for SNMP."])
      expect{ value.next }.to raise_error(StopIteration)
    end
  end

  describe "#get_bulk" do
    let(:oid) { "sysORDescr" }
    let(:oid_code) { "1.3.6.1.2.1.1.9.1.3" }
    let(:value) { subject.get_bulk(oid) }
    let(:options) { host_options.merge(context: "a172334d7d97871b72241397f713fa12") }
    it "fetches the varbinds for the next oid" do
      expect(value.next).to eq(["#{oid_code}.1","The SNMP Management Architecture MIB."])
      expect(value.next).to eq(["#{oid_code}.2","The MIB for Message Processing and Dispatching."])
      expect(value.next).to eq(["#{oid_code}.3","The management information definitions for the SNMP User-based Security Model."])
      expect(value.next).to eq(["#{oid_code}.4","The MIB module for SNMPv2 entities"])
      expect(value.next).to eq(["#{oid_code}.5","The MIB module for managing TCP implementations"])
      expect(value.next).to eq(["#{oid_code}.6","The MIB module for managing IP and ICMP implementations"])
      expect(value.next).to eq(["#{oid_code}.7","The MIB module for managing UDP implementations"])
      expect(value.next).to eq(["#{oid_code}.8","View-based Access Control Model for SNMP."])
      expect(value.next).to eq(["1.3.6.1.2.1.1.9.1.4.1",2])
      expect(value.next).to eq(["1.3.6.1.2.1.1.9.1.4.2",2])
      expect{ value.next }.to raise_error(StopIteration)
    end
  end

 
  # TODO: use this oid to test error calls
  #  let(:oid) { "SNMPv2-MIB::sysORDescr.1" }

  describe "#set" do
    let(:options) { host_options.merge(context: "0886e1397d572377c17c15036a1e6c66") } # write cache
    let(:oid) { "sysUpTimeInstance" }
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
