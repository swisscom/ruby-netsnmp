# frozen_string_literal: true

RSpec.describe NETSNMP::MIB do
  describe ".oid" do
    it { expect(described_class.oid("1.2.3.4")).to eq("1.2.3.4") }
    it { expect(described_class.oid("ifTable")).to eq("1.3.6.1.2.1.2.2") }
    it { expect(described_class.oid("sysDescr.0")).to eq("1.3.6.1.2.1.1.1.0") }
    it { expect(described_class.oid("ifTable.1.23")).to eq("1.3.6.1.2.1.2.2.1.23") }
    it { expect(described_class.oid("IF-MIB::ifTable.1.23")).to eq("1.3.6.1.2.1.2.2.1.23") }
    it { expect(described_class.oid("IFMIB::ifTable.1.23")).to be_nil }
    it { expect(described_class.oid("IF-MIB::")).to be_nil }
  end

  describe ".identifier" do
    it { expect(described_class.identifier("1.3.6.1.2.1.2.2.3.45")).to eq("IF-MIB::ifTable.3.45") }
    it { expect(described_class.identifier("1.3.6.1.2.1.1.0")).to eq("SNMPv2-MIB::system.0") }
    it { expect(described_class.identifier("1.2.3.4")).to be_nil }
  end

  describe "parse" do
    let(:object) { described_class.parse(mib) }

    describe "object type" do
      let(:mib) do
        <<-MIB
TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
  OBJECT-TYPE
    FROM SNMPv2-SMI;
testObjectType OBJECT-TYPE
    SYNTAX          Integer32
    UNITS           "seconds"
    MAX-ACCESS      accessible-for-notify
    STATUS          current
    DESCRIPTION     "Test object"
    REFERENCE       "ABC"
 ::= { 1 3 }
END
        MIB
      end

      it { expect(object.context["testObjectType"].name).to eq([1, 3]) }
      it { expect(object.context["testObjectType"].status).to eq("current") }
      it { expect(object.context["testObjectType"].description).to eq("Test object") }
      it { expect(object.context["testObjectType"].reference).to eq("ABC") }
      it { expect(object.context["testObjectType"].max_access).to eq("accessible-for-notify") }
      it { expect(object.context["testObjectType"].units).to eq("seconds") }
    end

    describe "object type integer" do
      let(:mib) do
        <<-MIB
TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
  OBJECT-TYPE,
  Integer32
    FROM SNMPv2-SMI;
testObjectType OBJECT-TYPE
    SYNTAX          Integer32
    MAX-ACCESS      read-only
    STATUS          current
    DESCRIPTION     "Test object"
    DEFVAL          { 123456 }
 ::= { 1 3 }
END
        MIB
      end

      it { expect(object.context["testObjectType"].syntax).to eq(123456) }
    end

    describe "object type enum" do
      let(:mib) do
        <<-OUT
TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
  OBJECT-TYPE
    FROM SNMPv2-SMI;
testObjectType OBJECT-TYPE
    SYNTAX          INTEGER  {
                        enable(1),
                        disable(2)
                    }
    MAX-ACCESS      read-only
    STATUS          current
    DESCRIPTION     "Test object"
    DEFVAL          { enable }
 ::= { 1 3 }
END
        OUT
      end

      it { expect(object.context["testObjectType"].syntax).to eq(1) }
    end

    describe "object type string" do
      let(:mib) do
        <<-MIB
TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
  OBJECT-TYPE
    FROM SNMPv2-SMI;
testObjectType OBJECT-TYPE
    SYNTAX          OCTET STRING
    MAX-ACCESS      read-only
    STATUS          current
    DESCRIPTION     "Test object"
    DEFVAL          { "test value" }
 ::= { 1 3 }
END
        MIB
      end

      it { expect(object.context["testObjectType"].syntax).to eq("test value") }
    end

    describe "object identity" do
      let(:mib) do
        <<-MIB
TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    OBJECT-IDENTITY
FROM SNMPv2-SMI;
testObject OBJECT-IDENTITY
    STATUS          current
    DESCRIPTION     "Initial version"
    REFERENCE       "ABC"
 ::= { 1 3 }
END
        MIB
      end

      it { expect(object.context["textObject"].name).to eq([1, 3]) }
      it { expect(object.context["textObject"].description).to eq("Initial version") }
      it { expect(object.context["textObject"].reference).to eq("ABC") }
    end
  end
end
