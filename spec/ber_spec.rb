RSpec.describe NETSNMP::BER do
  let(:encoded) { decoded.reverse }
  context "of primitive types" do
    let(:decoded) { { true => "\x01\x01\xFF", 
                      false => "\x01\x01\x00" } }
    describe "booleans" do
      it "decodes"
      it "encodes" do
        decoded.each do |decoded, encoded|
          expect( subject.encode(decoded) ).to eq(encoded.b)
        end
      end
    end
    describe "integer" do
      let(:decoded) { {
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
      } }
      it "decodes"
      it "encodes" do
        decoded.each do |decoded, encoded|
          expect(subject.encode(decoded)).to eq(encoded.b)
        end
      end
    end
    describe "string" do
      let(:decoded) { {
        "\u00e5".force_encoding("UTF-8") => "\x04\x02\xC3\xA5",
        "teststring".encode("US-ASCII") => "\x04\nteststring",
        ["6a31b4a12aa27a41aca9603f27dd5116"].pack("H*") => "\x04\x10" + "j1\xB4\xA1*\xA2zA\xAC\xA9`?'\xDDQ\x16",
        "\x81" => "\x04\x01\x81"
      } }
      it "decodes"
      it "encodes" do
        decoded.each do |decoded, encoded|
          expect(subject.encode(decoded)).to eq(encoded.b)
        end
      end

      context "if wanting to encode the data as it is" do
        it { expect(subject.encode(["6a31b4a12aa27a41aca9603f27dd5116"].pack("H*"), raw: true)).
               to eq("\x04\x10" + "j1\xB4\xA1*\xA2zA\xAC\xA9`?'\xDDQ\x16".b) }
      end
    end
    describe "nil" do
      it("decodes")
      it("encodes") { expect(subject.encode(nil)).to eq("\x05\x00".b) }
    end
  end

end
