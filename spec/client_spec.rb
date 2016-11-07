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
      let(:get_oid) { "1.3.6.1.2.1.1.5.0" }
      let(:next_oid) { "1.3.6.1.2.1.1.5.0" }
      let(:walk_oid) { "1.3.6.1.2.1.1" }
      let(:set_oid) { "1.3.6.1.2.1.1.1.0" }
      let(:get_result) { "DEVICE-192.168.1.1" }
      let(:next_result) { "The Cloud" }
      let(:walk_result) { <<-WALK
1.3.6.1.2.1.1.1.0: Device description
1.3.6.1.2.1.1.2.0: 1.3.6.1.4.1.3454
1.3.6.1.2.1.1.3.0: 78171676
1.3.6.1.2.1.1.4.0: The Owner
1.3.6.1.2.1.1.5.0: DEVICE-192.168.1.1
1.3.6.1.2.1.1.6.0: The Cloud
1.3.6.1.2.1.1.7.0: 72
1.3.6.1.2.1.1.8.0: 0
WALK
      }
      let(:set_oid_result) { "SNMPv1 trap sender" }
    end
  end
  describe "v2" do
    it_behaves_like "an snmp client" do
      let(:protocol_options) { {
        version: "2c",
        community: "public"
      } }
      let(:get_oid) { "1.3.6.1.2.1.1.5.0" }
      let(:next_oid) { "1.3.6.1.2.1.1.5.0" }
      let(:walk_oid) { "1.3.6.1.2.1.1" }
      let(:set_oid) { "1.3.6.1.2.1.1.1.0" }
      let(:get_result) { "DEVICE-192.168.1.1" }
      let(:next_result) { "The Cloud" }
      let(:walk_result) { <<-WALK
1.3.6.1.2.1.1.1.0: Device description
1.3.6.1.2.1.1.2.0: 1.3.6.1.4.1.3454
1.3.6.1.2.1.1.3.0: 78171676
1.3.6.1.2.1.1.4.0: The Owner
1.3.6.1.2.1.1.5.0: DEVICE-192.168.1.1
1.3.6.1.2.1.1.6.0: The Cloud
1.3.6.1.2.1.1.7.0: 72
1.3.6.1.2.1.1.8.0: 0
WALK
      }

    end
  end


  describe "v3" do
    let(:extra_options) { {} }
    let(:version_options) { {
      version: "3",
      context: "a172334d7d97871b72241397f713fa12",
    } }
    let(:get_oid) { "1.3.6.1.2.1.1.5.0" }
    let(:next_oid) { "1.3.6.1.2.1.1.5.0" }
    let(:walk_oid) { "1.3.6.1.2.1.1.9.1.3" }
    let(:get_result) { "tt" }
    let(:next_result) { "KK12" }

    context "with a no auth no priv policy" do
      let(:user_options) { { username: "unsafe", security_level: :noauth } }
      it_behaves_like "an snmp client" do
        let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
      end
    end
    context "with an only auth policy" do
      let(:user_options) { { username: "author", security_level: :auth_no_priv, 
                             auth_password: "authpass", auth_protocol: :md5 } }
      it_behaves_like "an snmp client" do
        let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
      end
    end
    context "with an auth priv policy" do
      let(:user_options) { { username: "simulator", auth_password: "auctoritas",
                             auth_protocol: :md5, priv_password: "privatus",
                             priv_protocol: :des } }
      it_behaves_like "an snmp client" do
        let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
      end
#      context "with a wrong auth password" do
#        let(:extra_options) { { auth_password: "auctoritas2", timeout: 5 } }
#        it { 
#          expect { 
#            subject.get(oid)
#          }.to raise_error(NETSNMP::ConnectionFailed) 
#        }
#      end
#      context "with a wrong priv password" do
#        let(:extra_options) { { priv_password: "privatus2", timeout: 5 } }
#        it { 
#          expect { 
#            subject.get(oid)
#          }.to raise_error(NETSNMP::ConnectionFailed) 
#        }
#      end
#
#      context "with an unexisting user" do
#        let(:extra_options) { { username: "simulata", timeout: 5 } }
#        it { 
#          expect { 
#            subject.get(oid)
#          }.to raise_error(NETSNMP::ConnectionFailed) 
#        }
#      end
    end
  end
end
