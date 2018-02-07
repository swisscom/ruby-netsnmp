# frozen_string_literal: true

RSpec.describe NETSNMP::OID do
  # let(:code) { "SNMPv2-MIB::sysDescr.0" }
  let(:code) { "1.3.6.1.2.1.1.1.0" }
  subject { described_class.build(code) }

  describe ".build" do
    it { expect(described_class.build([1, 3, 6, 1, 2, 1, 1, 1, 0]).to_s).to eq(code) }
    it { expect(described_class.build(".#{code}").to_s).to eq(code) }
    it { expect { described_class.build("blablabla") }.to raise_error(NETSNMP::Error) }
  end

  describe ".to_asn" do
    it { expect(described_class.to_asn(subject).to_der).to eq("\x06\b+\x06\x01\x02\x01\x01\x01\x00".b) }
  end
end
