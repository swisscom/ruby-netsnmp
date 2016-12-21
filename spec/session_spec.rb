RSpec.describe NETSNMP::Session do
  let(:host) { "localhost" }
  let(:options) { {
    version: '2c', 
    context: "public",
    port: SNMPPORT
  } }
  subject { described_class.new(host, options) }
  after { subject.close }

end
