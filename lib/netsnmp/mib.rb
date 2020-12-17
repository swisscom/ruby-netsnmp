# frozen_string_literal: true

module NETSNMP
  module MIB
    module_function

    DEFAULT_PATH = "/usr/share/snmp/mibs/"

    def oid(identifier); end

    def identifier(oid); end

    # The following SMIv2 grammar relaxation parameters are defined:
    #        * supportSmiV1Keywords - parses SMIv1 grammar
    #        * supportIndex - tolerates ASN.1 types in INDEX clause
    #        * commaAtTheEndOfImport - tolerates stray comma at the end of IMPORT section
    #        * commaAtTheEndOfSequence - tolerates stray comma at the end of sequence of elements in MIB
    #        * mixOfCommasAndSpaces - tolerate a mix of comma and spaces in MIB enumerations
    #        * uppercaseIdentifier - tolerate uppercased MIB identifiers
    #        * lowcaseIdentifier - tolerate lowercase MIB identifiers
    #        * curlyBracesAroundEnterpriseInTrap - tolerate curly braces around enterprise ID in TRAP MACRO
    #        * noCells - tolerate missing cells (XXX)
  end
end
