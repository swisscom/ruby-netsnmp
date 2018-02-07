# frozen_string_literal: true

# from https://ask.wireshark.org/questions/14002/how-to-decode-timeticks-hundreds-seconds-to-readable-date-time
RSpec.describe NETSNMP::Timetick do
  subject { described_class.new(1525917187) }

  describe "as an integer" do
    it { expect((1 + subject).to_i).to be(1525917188) }
  end

  describe "as an embedded string" do
    it { expect(subject.to_s).to eq("Timeticks: (1525917187) 176 days, 14:39:31.87") }
  end
end
