RSpec.describe NETSNMP::Varbind do
  describe NETSNMP::RequestVarbind do
    describe "#to_ber" do
      it { expect(described_class.new(".1.3.6.1.2.1.1.1.0").to_ber).to eq("0\f\006\b+\006\001\002\001\001\001\000\005\000".b) }
    end
  end


  describe NETSNMP::ResponseVarbind do
  end
end
