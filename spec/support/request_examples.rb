# frozen_string_literal: true

RSpec.shared_examples "an snmp client" do
  let(:device_options) do
    {
      host: SNMPHOST,
      port: SNMPPORT
    }
  end
  let(:protocol_options) { {} }
  let(:extra_options) { {} }
  let(:options) { protocol_options.merge(device_options).merge(extra_options) }

  subject { described_class.new(**options) }

  describe "#get" do
    let(:value) { subject.get(oid: get_oid) }
    it "fetches the varbinds for a given oid" do
      expect(value).to eq(get_result)
    end
    context "with multiple oids" do
      let(:value) { subject.get({ oid: get_oid }, oid: next_oid) }
      it "returns the values for both" do
        expect(value).to be_a(Array)
        expect(value).to include(get_result)
        expect(value).to include(next_result)
      end
    end
  end

  describe "#get_next" do
    let(:varbind) { subject.get_next(oid: get_oid) }
    it "fetches the varbinds for the next oid" do
      oid, value = varbind
      expect(value).to start_with(next_result)
      expect(oid).to eq(next_oid)
    end
  end

  describe "#walk" do
    let(:value) { subject.walk(oid: walk_oid) }
    it "fetches the varbinds for the next oid" do
      value.each do |oid, val|
        match = walk_result[oid]
        case match
        when String
          expect(val.to_s).to eq(match)
        when Regexp
          expect(val.to_s).to match(match)
        else
          next
        end
      end
    end
  end
end
