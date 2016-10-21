RSpec.describe NETSNMP::PDU do
  let(:get_request_oid) { ".1.3.6.1.2.1.1.1.0" }
  let(:pdu_get_request) { "0'\002\001\000\004\006public\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000" }
  let(:pdu_response) { "0+\002\001\000\004\006public\242\036\002\002'\017\002\001\000\002\001\0000\0220\020\006\b+\006\001\002\001\001\001\000\004\004test" }

  describe NETSNMP::RequestPDU do
    subject { described_class.build(:get, 
                                      version: 0,
                                      request_id: 16170,
                                      community: "public") }
    describe "#to_ber" do
      context "v2c" do
        before do
           subject.add_varbind(get_request_oid)
        end
        it { expect(subject.to_ber).to eq(pdu_get_request.b) }
      end
    end
  end

  describe NETSNMP::ResponsePDU do
    subject { described_class.build(:response, pdu_response) }
    describe "v1" do
      it { expect(subject[:version]).to be(0) }
      it { expect(subject[:community]).to eq("public") }
      it { expect(subject[:request_id]).to be(9999) }
      it { expect(subject[:error_status]).to be(0) }
      it { expect(subject[:error_index]).to be(0) }

      it { expect(subject.varbinds.length).to be(1) }
      it { expect(subject.varbinds[0].oid).to eq(".1.3.6.1.2.1.1.1.0") } 
      it { expect(subject.varbinds[0].value).to eq("test") } 

    end
  end
end
