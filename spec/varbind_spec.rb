# frozen_string_literal: true

RSpec.describe NETSNMP::Varbind do
  describe "#to_der" do
    it { expect(described_class.new(".1.3.6.1.2.1.1.1.0").to_der).to eq("0\f\006\b+\006\001\002\001\001\001\000\005\000".b) }

    context "application specific" do
      it "converts ip addresses" do
        ipaddr = IPAddr.new("10.11.104.2")
        varbind = described_class.new(".1.3.6.1.4.1.2011.6.3.1.1.0", value: ipaddr)
        expect(varbind.to_der).to end_with("@\x04\n\vh\x02".b)
        asn = varbind.to_asn.value.last
        expect(varbind.convert_application_asn(asn)).to eq(ipaddr)
      end
      it "converts custom timeticks" do
        timetick = NETSNMP::Timetick.new(1) # yes, one timetick
        varbind = described_class.new(".1.3.6.1.2.1.1.3.0", value: timetick)
        expect(varbind.to_der).to end_with("\x04\x00\x00\x00\x01".b) # ends with an octet string rep of 1 timetick
        asn = varbind.to_asn.value.last
        expect(varbind.convert_application_asn(asn)).to eq(timetick)
      end
      context "when passed a type" do
        it "converts gauge32" do
          gauge = 805
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :gauge, value: gauge)
          expect(varbind.to_der).to end_with("B\x02\x03%".b)
          asn = varbind.to_asn.value.last
          expect(varbind.convert_application_asn(asn)).to eq(gauge)
        end
        it "converts counter32" do
          counter = 998932
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :counter32, value: counter)
          expect(varbind.to_der).to end_with("\x0F>\x14".b)
          asn = varbind.to_asn.value.last
          expect(varbind.convert_application_asn(asn)).to eq(counter)
        end
        it "converts counter64" do
          counter = 998932
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :counter64, value: counter)
          expect(varbind.to_der).to end_with("\x0F>\x14".b)
          asn = varbind.to_asn.value.last
          expect(varbind.convert_application_asn(asn)).to eq(counter)

          counter = 4294967296
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :counter64, value: counter)
          expect(varbind.to_der).to end_with("\x01\x00\x00\x00\x00".b)
          asn = varbind.to_asn.value.last
          expect(varbind.convert_application_asn(asn)).to eq(counter)

          counter = 309084502
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :counter64, value: counter)
          expect(varbind.to_der).to include("F\x04".b)
          asn = varbind.to_asn.value.last
          expect(varbind.convert_application_asn(asn)).to eq(counter)

          counter = 2_613_579_752_238
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :counter64, value: counter)
          expect(varbind.to_der).to include("F\x06".b)
          asn = varbind.to_asn.value.last
          expect(varbind.convert_application_asn(asn)).to eq(counter)
        end
        it "converts integer ticks" do
          timetick = 1
          varbind = described_class.new(".1.3.6.1.2.1.1.3.0", type: :timetick, value: timetick)
          expect(varbind.to_der).to end_with("\x04\x00\x00\x00\x01".b)
          asn = varbind.to_asn.value.last
          expect(varbind.convert_application_asn(asn)).to eq(timetick)
        end
      end
    end
  end
end
