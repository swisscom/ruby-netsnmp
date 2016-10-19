RSpec.describe NETSNMP::BER do
  describe ".encoding" do
    context "of primitive types" do
      describe "integer" do
        {
          0           => "\x02\x01\x00",
          1           => "\x02\x01\x01",
          127         => "\x02\x01\x7F",
          128         => "\x02\x02\x00\x80",
          255         => "\x02\x02\x00\xFF",
          256         => "\x02\x02\x01\x00",
          65535       => "\x02\x03\x00\xFF\xFF",
          65536       => "\x02\x03\x01\x00\x00",
          8388607     => "\x02\x03\x7F\xFF\xFF",
          8388608     => "\x02\x04\x00\x80\x00\x00",
          16_777_215  => "\x02\x04\x00\xFF\xFF\xFF",
          0x01000000  => "\x02\x04\x01\x00\x00\x00",
          0x3FFFFFFF  => "\x02\x04\x3F\xFF\xFF\xFF",
          0x4FFFFFFF  => "\x02\x04\x4F\xFF\xFF\xFF",

          # Some odd samples...
          5           => "\x02\x01\x05",
          500         => "\x02\x02\x01\xf4",
          50_000      => "\x02\x03\x00\xC3\x50",
          5_000_000_000 => "\x02\x05\x01\x2a\x05\xF2\x00",

          # negatives
          -1          => "\x02\x01\xFF",
          -127        => "\x02\x01\x81",
          -128        => "\x02\x01\x80",
          -255        => "\x02\x02\xFF\x01",
          -256        => "\x02\x02\xFF\x00",
          -65535      => "\x02\x03\xFF\x00\x01",
          -65536      => "\x02\x03\xFF\x00\x00",
          -65537      => "\x02\x03\xFE\xFF\xFF",
          -8388607    => "\x02\x03\x80\x00\x01",
          -8388608    => "\x02\x03\x80\x00\x00",
          -16_777_215 => "\x02\x04\xFF\x00\x00\x01",
        }.each do |i, ber|
          it { expect(subject.encode(i)).to eq(ber.b) }
        end
      end
      describe "string"
      describe "null"
      describe "oid" do
#        let(:val) { ".1.3.6.1.2.1.1.1.0" }
#        # ASCII
#        it { is_expected.to eq("") }
#        # HEXA
#        it { is_expected.to eq("") }
      end
    end

    context "of complex types" do

    end
  end


end
