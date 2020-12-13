# frozen_string_literal: true

RSpec.describe NETSNMP::V3Session do
  let(:security_options) do
    { username: "authprivmd5des", auth_password: "maplesyrup",
      auth_protocol: :md5, priv_password: "maplesyrup",
      priv_protocol: :des, security_level: :auth_priv }
  end
  it "generates the security parameters handler" do
    sess = described_class.new(**security_options.merge(host: SNMPHOST, port: SNMPPORT))
    # not generated yet
    expect(sess.instance_variable_get(:@security_parameters)).to be_a(NETSNMP::SecurityParameters)
  end

  it "allows to pass a custom one" do
    sec_params = NETSNMP::SecurityParameters.new(**security_options)
    sess = described_class.new(host: SNMPHOST, port: SNMPPORT, security_parameters: sec_params)
    # not generated yet
    expect(sess.instance_variable_get(:@security_parameters)).to be(sec_params)
  end

  it "fails if the pass object doesn't follow the expected api" do
    expect { described_class.new(host: SNMPHOST, port: SNMPPORT, security_parameters: double) }.to raise_error(NETSNMP::Error)
  end
end
