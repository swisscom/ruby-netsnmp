RSpec.describe NETSNMP::OID do
  #let(:code) { "SNMPv2-MIB::sysDescr.0" }
  let(:code) { "1.3.6.1.2.1.1.1.0" }
  subject { described_class.new(code) }

  it { expect { described_class.new("blablabla") }.to raise_error(NETSNMP::OID::Error) }

  describe "#to_ber" do
    it { expect(subject.to_ber).to eq("\x06\b+\x06\x01\x02\x01\x01\x01\x00".b) }
  end
end
