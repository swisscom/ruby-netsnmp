RSpec.describe NETSNMP::Session do
  let(:host) { "localhost" }
  let(:options) { {
    version: '2c', 
    context: "public",
    port: SNMPPORT
  } }
  subject { described_class.new(host, options) }
  after { subject.close }


  describe "#send" do
    let(:pointer) { double(:pointer) }
    let(:pdu) { double(:pdu, pointer: pointer) }
    let(:response) { double(:response) }
    let(:reqid) { double(:requestid) }
    let(:requests) { {} }

    before do
      allow(pdu).to receive(:[]).with(:reqid).and_return(reqid) 
      allow(requests).to receive(:[]).with(reqid).and_return([:success, response])
    end

    it "sends and receives a pdu" do
      expect(IO).to receive(:select).twice.and_return([[], []])
      expect(NETSNMP::Core::LibSNMP).to receive(:snmp_sess_async_send).with(subject.signature, pointer, instance_of(FFI::Function), nil)
      expect(subject).to receive(:handle_response).and_return(response)
      expect(subject.send(pdu)).to be(response)
    end
    

  end

end
