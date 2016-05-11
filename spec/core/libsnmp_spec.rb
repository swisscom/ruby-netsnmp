RSpec.describe NETSNMP::Core::LibSNMP do
  subject { described_class }
  it "exposes initialization and shutdown methods" do
    [:init_snmp, :snmp_perror].each do |meth| 
      is_expected.to respond_to(meth)
    end
  end

  it "exposes netsnmp session handling methods" do
    [:snmp_sess_init, :snmp_sess_open, :snmp_sess_close, :generate_Ku].each do |meth|
      is_expected.to respond_to(meth)
    end
  end

  it "exposes netsnmp read API" do
    [:snmp_sess_synch_response, :snmp_sess_send].each do |meth|
      is_expected.to respond_to(meth)
    end
  end

  it "exposes netsnmp session async send/read" do
    [:snmp_sess_async_send, :snmp_sess_select_info, :snmp_sess_read].each do |meth|
      is_expected.to respond_to(meth)
    end
  end

  it "exposes the pdu API" do
    [:snmp_pdu_create, :snmp_free_pdu, :snmp_pdu_add_variable].each do |meth|
      is_expected.to respond_to(meth)
    end
  end
end
