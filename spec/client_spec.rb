# frozen_string_literal: true

require_relative "support/request_examples"

RSpec.describe NETSNMP::Client do
  let(:host) { SNMPHOST }

  let(:device_options) do
    {
      peername: SNMPHOST,
      port: SNMPPORT
    }
  end
  describe "v1" do
    it_behaves_like "an snmp client" do
      let(:protocol_options) do
        {
          version: "1",
          community: "public"
        }
      end
      let(:get_oid) { "1.3.6.1.2.1.1.5.0" }
      let(:next_oid) { "1.3.6.1.2.1.1.6.0" }
      let(:walk_oid) { "1.3.6.1.2.1.1" }
      let(:set_oid) { "sysUpTime.0" } # sysUpTimeInstance
      let(:get_result) { "DEVICE-192.168.1.1" }
      let(:next_result) { "The Cloud" }
      let(:walk_result) do
        <<-WALK
1.3.6.1.2.1.1.1.0: Device description
1.3.6.1.2.1.1.2.0: 1.3.6.1.4.1.3454
1.3.6.1.2.1.1.3.0: Timeticks: (78171676) 9 days, 1:8:36.76
1.3.6.1.2.1.1.4.0: The Owner
1.3.6.1.2.1.1.5.0: DEVICE-192.168.1.1
1.3.6.1.2.1.1.6.0: The Cloud
1.3.6.1.2.1.1.7.0: 72
1.3.6.1.2.1.1.8.0: Timeticks: (0) 0 days, 0:0:0.0
        WALK
      end
      let(:set_oid_result) { 43 }
    end
  end
  describe "v2" do
    it_behaves_like "an snmp client" do
      let(:protocol_options) do
        {
          version: "2c",
          community: "public"
        }
      end
      let(:get_oid) { "sysName.0" }
      let(:next_oid) { "1.3.6.1.2.1.1.6.0" }
      let(:walk_oid) { "system" }
      let(:set_oid) { "sysUpTime.0" }
      let(:get_result) { "DEVICE-192.168.1.1" }
      let(:next_result) { "The Cloud" }
      let(:walk_result) do
        <<-WALK
1.3.6.1.2.1.1.1.0: Device description
1.3.6.1.2.1.1.2.0: 1.3.6.1.4.1.3454
1.3.6.1.2.1.1.3.0: Timeticks: (78171676) 9 days, 1:8:36.76
1.3.6.1.2.1.1.4.0: The Owner
1.3.6.1.2.1.1.5.0: DEVICE-192.168.1.1
1.3.6.1.2.1.1.6.0: The Cloud
1.3.6.1.2.1.1.7.0: 72
1.3.6.1.2.1.1.8.0: Timeticks: (0) 0 days, 0:0:0.0
        WALK
      end
      let(:set_oid_result) { 43 }

      context "when the returned value is a hex-string" do
        let(:protocol_options) do
          {
            version: "2c",
            community: "foreignformats/winxp1"
          }
        end
        let(:hex_get_oid) { "1.3.6.1.2.1.25.3.7.1.3.10.1" }
        let(:hex_get_result) { "\x01\x00\x00\x00" }
        let(:hex_get_output) { "01 00 00 00" }
        let(:value) { subject.get(oid: hex_get_oid) }

        it "returns the string, which outputs the hex-representation" do
          expect(value).to eq(hex_get_result)
          expect(value.inspect).to include(hex_get_output)
        end
      end
    end
  end

  describe "v3" do
    let(:extra_options) { {} }
    let(:version_options) do
      {
        version: "3",
        context: "a172334d7d97871b72241397f713fa12"
      }
    end
    let(:get_oid) { "sysName.0" }
    let(:next_oid) { "1.3.6.1.2.1.1.6.0" }
    let(:set_oid) { "sysUpTime.0" } # sysUpTimeInstance
    let(:walk_oid) { "1.3.6.1.2.1.1.9.1.3" }
    let(:get_result) { "tt" }
    let(:next_result) { "KK12" }
    let(:walk_result) do
      <<-WALK
1.3.6.1.2.1.1.9.1.3.1: The SNMP Management Architecture MIB.
1.3.6.1.2.1.1.9.1.3.2: The MIB for Message Processing and Dispatching.
1.3.6.1.2.1.1.9.1.3.3: The management information definitions for the SNMP User-based Security Model.
1.3.6.1.2.1.1.9.1.3.4: The MIB module for SNMPv2 entities
1.3.6.1.2.1.1.9.1.3.5: The MIB module for managing TCP implementations
1.3.6.1.2.1.1.9.1.3.6: The MIB module for managing IP and ICMP implementations
1.3.6.1.2.1.1.9.1.3.7: The MIB module for managing UDP implementations
1.3.6.1.2.1.1.9.1.3.8: View-based Access Control Model for SNMP.
      WALK
    end
    let(:set_oid_result) { 43 }
    context "with a no auth no priv policy" do
      let(:user_options) { { username: "unsafe", security_level: :noauth } }
      it_behaves_like "an snmp client" do
        let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        # why is this here? that variation/notification community causes the simulagtor to go down
        # until I find the origin of the issue and patched it with an appropriated community, this
        # is here so that I test the set call at least once, although I'm sure it'll work always
        # for v3
        describe "#set" do
          let(:extra_options) { { context: "0886e1397d572377c17c15036a1e6c66" } }
          it "updates the value of the oid" do
            prev_value = subject.get(oid: set_oid)
            expect(prev_value).to be_a(Integer)

            # without type
            subject.set(oid: set_oid, value: set_oid_result)
            expect(subject.get(oid: set_oid)).to eq(set_oid_result)

            subject.set(oid: set_oid, value: prev_value)
          end
        end
      end
    end
    context "with an only auth policy" do
      context "speaking md5" do
        let(:user_options) do
          { username: "authmd5", security_level: :auth_no_priv,
            auth_password: "maplesyrup", auth_protocol: :md5 }
        end
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "speaking sha" do
        let(:user_options) do
          { username: "authsha", security_level: :auth_no_priv,
            auth_password: "maplesyrup", auth_protocol: :sha }
        end
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
    end
    context "with an auth priv policy" do
      context "auth in md5, encrypting in des" do
        let(:user_options) do
          { username: "authprivmd5des", auth_password: "maplesyrup",
            auth_protocol: :md5, priv_password: "maplesyrup",
            priv_protocol: :des }
        end
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "auth in sha, encrypting in des" do
        let(:user_options) do
          { username: "authprivshades", auth_password: "maplesyrup",
            auth_protocol: :sha, priv_password: "maplesyrup",
            priv_protocol: :des }
        end
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }

          context "with wrong auth password and wrong encrypting password" do
            let(:user_options) do
              { username: "authprivmd5des", auth_password: "wrongpassword",
                auth_protocol: :md5, priv_password: "maplesyrup",
                priv_protocol: :des }
            end
            let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
            it "raises authentication error" do
              expect { subject.get(oid: get_oid) }.to raise_error(NETSNMP::Error, "Authentication failure (incorrect password, community or key)")
            end
          end
        end
      end

      context "auth in md5, encrypting in aes" do
        let(:user_options) do
          { username: "authprivmd5aes", auth_password: "maplesyrup",
            auth_protocol: :md5, priv_password: "maplesyrup",
            priv_protocol: :aes }
        end
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "auth in sha, encrypting in aes" do
        let(:user_options) do
          { username: "authprivshaaes", auth_password: "maplesyrup",
            auth_protocol: :sha, priv_password: "maplesyrup",
            priv_protocol: :aes }
        end
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
    end
  end
end
