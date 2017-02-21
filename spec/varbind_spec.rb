RSpec.describe NETSNMP::Varbind do
  describe "#to_der" do
    it { expect(described_class.new(".1.3.6.1.2.1.1.1.0").to_der).to eq("0\f\006\b+\006\001\002\001\001\001\000\005\000".b) }

    context "application specific" do
      it "converts ip addresses" do
        ipaddr = IPAddr.new("10.11.104.2")
        varbind = described_class.new(".1.3.6.1.4.1.2011.6.3.1.1.0", value: ipaddr)
        expect(varbind.to_der).to end_with("@\x04\n\vh\x02".b)
      end
      it "converts custom timeticks" do
        timetick = NETSNMP::Timetick.new(1) # yes, one timetick
        varbind = described_class.new(".1.3.6.1.2.1.1.3.0", value: timetick)
        expect(varbind.to_der).to end_with("\x04\x00\x00\x00\x01".b) # ends with an octet string rep of 1 timetick
      end
      context "when passed a type" do
        # TODO: tidy this for IP Addresses
        it "converts integer ticks" do
          timetick = 1
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :timetick, value: timetick)
          expect(varbind.to_der).to end_with("\x04\x00\x00\x00\x01".b)
        end
      end
    end
  end
end
