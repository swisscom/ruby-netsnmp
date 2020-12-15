# frozen_string_literal: true

RSpec.describe NETSNMP::Session do
  let(:host) { SNMPHOST }
  let(:options) do
    {
      version: "2c",
      context: "public",
      port: SNMPPORT
    }
  end
  subject { described_class.new(host: host, **options) }
  after { subject.close }
end
