RSpec.describe NETSNMP::Varbind do
  describe "#to_der" do
    it { expect(described_class.new(".1.3.6.1.2.1.1.1.0").to_der).to eq("0\f\006\b+\006\001\002\001\001\001\000\005\000".b) }
  end
end
