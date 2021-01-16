# frozen_string_literal: true

RSpec.describe NETSNMP::MIB do
  describe ".oid" do
    it { expect(described_class.oid("1.2.3.4")).to eq("1.2.3.4") }
    it { expect(described_class.oid("ifTable")).to eq("1.3.6.1.2.1.2.2") }
    it { expect(described_class.oid("sysDescr.0")).to eq("1.3.6.1.2.1.1.1.0") }
    it { expect(described_class.oid("ifTable.1.23")).to eq("1.3.6.1.2.1.2.2.1.23") }
    it { expect(described_class.oid("IF-MIB::ifTable.1.23")).to eq("1.3.6.1.2.1.2.2.1.23") }
    it { expect(described_class.oid("IFMIB::ifTable.1.23")).to be_nil }
    it { expect(described_class.oid("IF-MIB::")).to be_nil }
  end
end
