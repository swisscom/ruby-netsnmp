RSpec.describe NETSNMP::Core::Structures do
  describe NETSNMP::Core::Structures::Session do
    [:version, :retries, :timeout, :flags, :subsession, :next, :peername, :remote_port, :localname, :local_port, :authenticator, 
     :callback, :callback_magic, :community, :community_len, :rcvMsgMaxSize, :sndMsgMaxSize, :isAuthoritative, :contextEngineID,
     :contextEngineIDLen, :engineBoots, :engineTime, :contextName, :contextNameLen, :securityEngineID, :securityEngineIDLen, 
     :securityName, :securityNameLen, :securityAuthProto, :securityAuthProtoLen, :securityAuthKey, :securityAuthKeyLen, 
     :securityAuthLocalKey, :securityAuthLocalKeyLen, :securityPrivProto, :securityPrivProtoLen, :securityPrivKey, :securityPrivKeyLen,
     :securityPrivLocalKey, :securityPrivLocalKeyLen, :securityModel, :securityLevel, :paramName, :securityInfo, :myvoid].each do |attr| 
      it { expect(subject[attr]).not_to be_nil } 
    end
  end

  describe NETSNMP::Core::Structures::Vardata do
    [:integer, :string, :objid, :bitstring, :counter64, :float, :double].each do |attr|
      it { expect(subject[attr]).not_to be_nil }
    end
  end

  describe NETSNMP::Core::Structures::VariableList do
    [:next_variable, :name, :name_length, :type, :val, :val_len, :name_loc, :buf, :data, :dataFreeHook, :index].each do |attr|
      it { expect(subject[attr]).not_to be_nil }
    end
  end 

  describe NETSNMP::Core::Structures::PDU do
    [:version, :command, :reqid, :msgid, :transid, :sessid, :errstat, :errindex, :time, :flags, :securityModel, 
     :securityLevel, :msgParseModel, :transport_data, :transport_data_length, :tDomain, :tDomainLen, :variables, 
     :community, :community_len, :enterprise, :enterprise_length, :trap_type, :specific_type, :agent_addr, 
     :contextEngineID, :contextEngineIDLen, :contextName, :contextNameLen, :securityEngineID, :securityEngineIDLen, 
     :securityName, :securityNameLen, :priority, :range_subid, :securityStateRef].each do |attr|
      it { expect(subject[attr]).not_to be_nil }
    end 
  end

  describe NETSNMP::Core::Structures::SessionList do 
    [:next, :session, :transport, :internal].each do |attr|
      it { expect(subject[attr]).not_to be_nil }
    end
  end

  describe NETSNMP::Core::Structures::Transport do
    [:domain, :domain_length, :local, :local_length, :remote, :remote_length, 
     :sock, :flags, :data, :data_length, :msgMaxSize, :base_transport].each do |attr|
      it { expect(subject[attr]).not_to be_nil } 
    end
  end

  describe NETSNMP::Core::Structures::Counter64 do
    [:high, :low].each do |attr|
      it { expect(subject[attr]).not_to be_nil } 
    end
  end

end
