require 'celluloid/io'
require 'netsnmp/handlers/celluloid'
require_relative '../support/celluloid'

RSpec.describe NETSNMP::Celluloid::Client, type: :celluloid do
  include CelluloidHelpers
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
      value = within_io_actor { value = subject.get(oid) }
      expect(value).to eq("tt")
    end
  end
  
end
