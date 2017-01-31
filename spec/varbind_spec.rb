RSpec.describe NETSNMP::Varbind do
  describe "#to_der" do
    it { expect(described_class.new(".1.3.6.1.2.1.1.1.0").to_der).to eq("0\f\006\b+\006\001\002\001\001\001\000\005\000".b) }

    context "application specific" do
      it "converts ip addresses" do
        ipaddr = IPAddr.new("10.11.104.2")
        varbind = described_class.new(".1.3.6.1.4.1.2011.6.3.1.1.0", value: ipaddr)
        expect(varbind.to_der).to end_with("@\x04\n\vh\x02".b)
      end
    end
  end
end
