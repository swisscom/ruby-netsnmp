require 'em-synchrony'
require 'netsnmp/handlers/em'

RSpec.describe NETSNMP::EM::Client do
  let(:host) { "localhost" }
  let(:host_options) { {
    peername: "localhost",
    port: SNMPPORT,
    username: "simulator",
    auth_password: "auctoritas",
    auth_protocol: :md5,
    priv_password: "privatus",
    priv_protocol: :des
  } }

  subject { described_class.new(host, options) }

  describe "#get" do
    let(:oid) { "sysName.0" }
    let(:options) { host_options.merge(context: "a172334d7d97871b72241397f713fa12") }
    it "fetches the varbinds for a given oid" do
      value = nil
      EM.synchrony do
        begin
          value = subject.get(oid)
        ensure
          EM.stop_event_loop
        end
      end
      expect(value).to eq("tt")
    end
  end
  
end
