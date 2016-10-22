require_relative "support/request_examples"

RSpec.describe NETSNMP::Client do
  let(:host) { "localhost" }

  let(:device_options) { {
    peername: "localhost",
    port: SNMPPORT
  } }
  describe "v1" do
    it_behaves_like "an snmp client" do
      let(:protocol_options) { {
        version: "1",
        community: "public"
      } }
      let(:sysname) { "DEVICE-192.168.1.1" }
    end
  end
  describe "v2" do
    it_behaves_like "an snmp client" do
      let(:protocol_options) { {
        version: "2c",
        community: "public"
      } }
      let(:sysname) { "DEVICE-192.168.1.1" }
    end
  end


  describe "v3" do
    it_behaves_like "an snmp client" do 
      let(:extra_options) { {} }
      let(:protocol_options) { {
        version: "3",
        context: "a172334d7d97871b72241397f713fa12",
        username: "simulator",
        auth_password: "auctoritas",
        auth_protocol: :md5,
        priv_password: "privatus",
        priv_protocol: :des
      }.merge(extra_options) }
      let(:sysname) { "tt" }

      context "with a wrong auth password" do
        let(:extra_options) { { auth_password: "auctoritas2", timeout: 5 } }
        it { 
          expect { 
            subject.get(oid)
          }.to raise_error(NETSNMP::ConnectionFailed) 
        }
      end
      context "with a wrong priv password" do
        let(:extra_options) { { priv_password: "privatus2", timeout: 5 } }
        it { 
          expect { 
            subject.get(oid)
          }.to raise_error(NETSNMP::ConnectionFailed) 
        }
      end

      context "with an unexisting user" do
        let(:extra_options) { { username: "simulata", timeout: 5 } }
        it { 
          expect { 
            subject.get(oid)
          }.to raise_error(NETSNMP::ConnectionFailed) 
        }
      end
    end
  end
end
