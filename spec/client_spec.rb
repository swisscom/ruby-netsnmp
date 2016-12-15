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
      let(:next_oid) { "1.3.6.1.2.1.1.6.0" }
      let(:walk_oid) { "1.3.6.1.2.1.1" }
      let(:set_oid) {  "1.3.6.1.2.1.1.1.0" }
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
      let(:next_oid) { "1.3.6.1.2.1.1.6.0" }
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
    let(:next_oid) { "1.3.6.1.2.1.1.6.0" }
    let(:walk_oid) { "1.3.6.1.2.1.1.9.1.3" }
    let(:get_result) { "tt" }
    let(:next_result) { "KK12" }
    let(:walk_result) { <<-WALK
1.3.6.1.2.1.1.9.1.3.1: The SNMP Management Architecture MIB.
1.3.6.1.2.1.1.9.1.3.2: The MIB for Message Processing and Dispatching.
1.3.6.1.2.1.1.9.1.3.3: The management information definitions for the SNMP User-based Security Model.
1.3.6.1.2.1.1.9.1.3.4: The MIB module for SNMPv2 entities
1.3.6.1.2.1.1.9.1.3.5: The MIB module for managing TCP implementations
1.3.6.1.2.1.1.9.1.3.6: The MIB module for managing IP and ICMP implementations
1.3.6.1.2.1.1.9.1.3.7: The MIB module for managing UDP implementations
1.3.6.1.2.1.1.9.1.3.8: View-based Access Control Model for SNMP.
WALK
    }
    context "with a no auth no priv policy" do
      let(:user_options) { { username: "unsafe", security_level: :noauth } }
      it_behaves_like "an snmp client" do
        let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
      end
    end
    context "with an only auth policy" do
      context "speaking md5" do
        let(:user_options) { { username: "authmd5", security_level: :auth_no_priv, 
                               auth_password: "maplesyrup", auth_protocol: :md5 } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "speaking sha" do
        let(:user_options) { { username: "authsha", security_level: :auth_no_priv, 
                               auth_password: "maplesyrup", auth_protocol: :sha } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end

    end
    context "with an auth priv policy" do
      context "auth in md5, encrypting in des" do
        let(:user_options) { { username: "authprivmd5des", auth_password: "maplesyrup",
                               auth_protocol: :md5, priv_password: "maplesyrup",
                               priv_protocol: :des } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "auth in sha, encrypting in des" do
        let(:user_options) { { username: "authprivshades", auth_password: "maplesyrup",
                               auth_protocol: :sha, priv_password: "maplesyrup",
                               priv_protocol: :des } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end

      context "auth in md5, encrypting in aes" do
        let(:user_options) { { username: "authprivmd5aes", auth_password: "maplesyrup",
                               auth_protocol: :md5, priv_password: "maplesyrup",
                               priv_protocol: :aes } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "auth in sha, encrypting in aes" do
        let(:user_options) { { username: "authprivshaaes", auth_password: "maplesyrup",
                               auth_protocol: :sha, priv_password: "maplesyrup",
                               priv_protocol: :aes } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
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
