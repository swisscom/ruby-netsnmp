# frozen_string_literal: true

RSpec.describe NETSNMP::Session do
  let(:host) { "localhost" }
  let(:options) do
    {
      version: "2c",
      context: "public",
      port: SNMPPORT
    }
  end
  subject { described_class.new(host, options) }
  after { subject.close }
end
