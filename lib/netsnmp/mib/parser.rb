# frozen_string_literal: true

require "parslet"

module NETSNMP::MIB
  class Parser < Parslet::Parser
    root :mibfile

    def spaced(character = nil)
      if character.nil? && block_given?
        yield >> space.repeat
      else
        str(character) >> space.repeat
      end
    end

    def curly(atom)
      str("{") >> space.repeat >> atom >> space.repeat >> str("}")
    end

    def bracketed(atom)
      str("(") >> space.repeat >> atom >> space.repeat >> str(")")
    end

    def square_bracketed(atom)
      str("[") >> space.repeat >> atom >> space.repeat >> str("]")
    end

    def with_separator(atom, separator = nil)
      if separator
        sep = if separator.is_a?(String)
                space.repeat >> str(separator) >> space.repeat
              else
                separator
              end

        atom >> (sep >> atom).repeat
      else
        atom >> (space.repeat >> atom).repeat
      end
    end

    rule(:mibfile) do
      space.repeat >> modules.maybe
    end

    rule(:modules) do
      with_separator(mod)
    end

    rule(:mod) do
      spaced { module_name.as(:name) } >> module_oid >>
        spaced("DEFINITIONS") >> colon_colon_part >>
        spaced("BEGIN") >>
        exports_part.as(:exports) >>
        linkage_part.as(:imports) >>
        declaration_part.as(:declarations) >>
        spaced("END")
    end

    rule(:module_name) { uppercase_identifier }

    rule(:module_oid) do
      spaced { curly(object_identifier) }.maybe
    end

    rule(:declaration_part) do
      spaced { declarations }.maybe
    end

    rule(:exports_part) do
      spaced { exports_clause }.maybe
    end

    rule(:exports_clause) do
      spaced("EXPORTS") >> spaced { import_identifiers } >> str(";")
    end

    rule(:linkage_part) do
      spaced { linkage_clause }.maybe
    end

    rule(:linkage_clause) do
      spaced("IMPORTS") >> spaced { import_part } >> str(";")
    end

    rule(:import_part) do
      imports.maybe
    end

    rule(:imports) { with_separator(import) }

    rule(:import) do
      spaced { import_identifiers.as(:ids) } >> spaced("FROM") >> module_name.as(:name)
    end

    rule(:import_identifiers) { with_separator(import_identifier.as(:name), ",") }

    rule(:import_identifier) do
      lowercase_identifier | uppercase_identifier | imported_keyword
    end

    rule(:imported_keyword) do
      imported_smi_keyword |
        str("BITS") |
        str("Integer32")  |
        str("IpAddress")  |
        str("MANDATORY-GROUPS") |
        str("MODULE-COMPLIANCE") |
        str("MODULE-IDENTITY") |
        str("OBJECT-GROUP") |
        str("OBJECT-IDENTITY") |
        str("OBJECT-TYPE") |
        str("Opaque") |
        str("TEXTUAL-CONVENTION") |
        str("TimeTicks") |
        str("Unsigned32")
    end

    rule(:imported_smi_keyword) do
      str("AGENT-CAPABILITIES") |
        str("Counter32") |
        str("Counter64") |
        str("Gauge32") |
        str("NOTIFICATION-GROUP") |
        str("NOTIFICATION-TYPE") |
        str("TRAP-TYPE")
    end

    rule(:declarations) do
      with_separator(declaration)
    end

    rule(:declaration) do
      type_declaration |
        value_declaration |
        object_identity_clause |
        object_type_clause |
        traptype_clause |
        notification_type_clause |
        module_identity_clause |
        module_compliance_clause |
        object_group_clause |
        notification_group_clause |
        agent_capabilities_clause |
        macro_clause
    end

    rule(:macro_clause) do
      spaced { macro_name.as(:name) } >> spaced { str("MACRO").as(:type) } >> colon_colon_part >>
        spaced("BEGIN") >>
        # ignoring macro clauses
        match("^(?!END)").repeat >>
        spaced("END")
    end

    rule(:macro_name) do
      str("MODULE-IDENTITY") |
        str("OBJECT-TYPE") |
        str("TRAP-TYPE") |
        str("NOTIFICATION-TYPE") |
        str("OBJECT-IDENTITY") |
        str("TEXTUAL-CONVENTION") |
        str("OBJECT-GROUP") |
        str("NOTIFICATION-GROUP") |
        str("MODULE-COMPLIANCE") |
        str("AGENT-CAPABILITIES")
    end

    rule(:agent_capabilities_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("AGENT-CAPABILITIES").as(:type) } >>
        spaced("PRODUCT-RELEASE") >> spaced { text } >>
        spaced("STATUS") >> spaced { status } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { refer_part }.maybe >>
        spaced { module_part_capabilities }.maybe >>
        colon_colon_part >> curly(object_identifier)
    end

    rule(:module_part_capabilities) do
      modules_capabilities
    end

    rule(:modules_capabilities) do
      with_separator(module_capabilities)
    end

    rule(:module_capabilities) do
      spaced("SUPPORTS") >>
        module_name_capabilities >>
        spaced("INCLUDES") >> curly(capabilities_groups) >>
        spaced { variation_part }.maybe
    end

    rule(:module_name_capabilities) do
      spaced { uppercase_identifier } >> object_identifier | uppercase_identifier
    end

    rule(:capabilities_groups) do
      with_separator(capabilities_group)
    end

    rule(:capabilities_group) { objectIdentifier }

    rule(:variation_part) do
      variations
    end

    rule(:variations) do
      with_separator(variation)
    end

    rule(:variation) do
      spaced("VARIATION") >> object_identifier >>
        spaced { syntax_part }.maybe >>
        spaced { write_syntax_part } >>
        spaced { variation_access_part }.maybe >>
        spaced { creation_part }.maybe >>
        spaced { def_val_part }.maybe >>
        spaced("DESCRIPTION") >> text
    end

    rule(:variation_access_part) do
      spaced("ACCESS") >> variation_access
    end

    rule(:variation_access) { lowercase_identifier }

    rule(:creation_part) do
      spaced("CREATION-REQUIRES") >> curly(cells)
    end

    rule(:cells) { with_separator(cell, ",") }

    rule(:cell) { object_identifier }

    rule(:notification_group_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("NOTIFICATION-GROUP").as(:type) } >>
        spaced { notifications_part } >>
        spaced("STATUS") >> spaced { status } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { refer_part }.maybe >>
        colon_colon_part >> curly(object_identifier)
    end

    rule(:notifications_part) do
      spaced("NOTIFICATIONS") >> curly(notifications)
    end

    rule(:notifications) do
      with_separator(notification, ",")
    end

    rule(:notification) do
      notification_name
    end

    rule(:object_group_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("OBJECT-GROUP").as(:type) } >>
        spaced { object_group_objects_part } >>
        spaced("STATUS") >> spaced { status } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { refer_part }.maybe >>
        colon_colon_part >> curly(object_identifier)
    end

    rule(:object_group_objects_part) do
      spaced("OBJECTS") >> curly(objects)
    end

    rule(:module_compliance_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("MODULE-COMPLIANCE").as(:type) } >>
        spaced("STATUS") >> spaced { status } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { refer_part }.maybe >>
        spaced { compliance_modules } >>
        colon_colon_part >> curly(object_identifier)
    end

    rule(:compliance_modules) do
      with_separator(compliance_module)
    end

    rule(:compliance_module) do
      spaced { str("MODULE") >> (space_in_line.repeat(1) >> compliance_module_name).maybe } >>
        spaced { mandatory_part }.maybe >>
        compliances.maybe
    end

    rule(:compliance_module_name) do
      uppercase_identifier
    end

    rule(:mandatory_part) do
      spaced("MANDATORY-GROUPS") >> curly(mandatory_groups)
    end

    rule(:compliances) do
      with_separator(compliance).as(:compliances)
    end

    rule(:compliance) do
      compliance_group | compliance_object
    end

    rule(:compliance_group) do
      spaced { str("GROUP").as(:type) } >> spaced { object_identifier.as(:name) } >>
        spaced("DESCRIPTION") >> text
    end

    rule(:compliance_object) do
      spaced { str("OBJECT").as(:type) } >>
        spaced { object_identifier.as(:name) } >>
        spaced { syntax_part }.maybe >>
        spaced { write_syntax_part }.maybe >>
        spaced { access_part }.maybe >>
        spaced("DESCRIPTION") >> text
    end

    rule(:syntax_part) do
      spaced("SYNTAX") >> syntax.as(:syntax)
    end

    rule(:write_syntax_part) do
      (spaced("WRITE-SYNTAX") >> spaced { syntax }).maybe
    end

    rule(:access_part) do
      (spaced("MIN-ACCESS") >> spaced { access }).maybe
    end

    rule(:mandatory_groups) do
      with_separator(mandatory_group, ",").as(:groups)
    end

    rule(:mandatory_group) { object_identifier.as(:name) }

    rule(:module_identity_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("MODULE-IDENTITY").as(:type) } >>
        (spaced("SUBJECT-CATEGORIES") >> curly(category_ids)).maybe >>
        spaced("LAST-UPDATED") >> spaced { ext_utc_time } >>
        spaced("ORGANIZATION") >> spaced { text.as(:organization) } >>
        spaced("CONTACT-INFO") >> spaced { text.as(:contact_info) } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { revisions }.maybe >>
        colon_colon_part >> curly(object_identifier.as(:value))
    end

    rule(:ext_utc_time) { text }

    rule(:revisions) do
      with_separator(revision)
    end

    rule(:revision) do
      spaced("REVISION") >> spaced { ext_utc_time } >>
        spaced("DESCRIPTION") >>
        text
    end

    rule(:category_ids) do
      with_separator(category_id, ",")
    end

    rule(:category_id) do
      spaced { lowercase_identifier } >> bracketed(number) | lowercase_identifier
    end

    rule(:notification_type_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("NOTIFICATION-TYPE").as(:type) } >>
        spaced { notification_objects_part }.maybe >>
        spaced("STATUS") >> spaced { status } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { refer_part }.maybe >>
        colon_colon_part >> curly(notification_name)
    end

    rule(:notification_objects_part) do
      spaced("OBJECTS") >> curly(objects)
    end

    rule(:objects) do
      with_separator(object, ",")
    end

    rule(:object) do
      object_identifier
    end

    rule(:notification_name) do
      object_identifier
    end

    rule(:traptype_clause) do
      spaced { fuzzy_lowercase_identifier.as(:name) } >>
        spaced { str("TRAP-TYPE").as(:type) } >> spaced { enterprise_part } >>
        spaced { var_part }.maybe >>
        spaced { descr_part }.maybe >>
        spaced { refer_part }.maybe >>
        colon_colon_part >> number
    end

    rule(:enterprise_part) do
      spaced("ENTERPRISE") >> object_identifier |
        spaced("ENTERPRISE") >> curly(object_identifier)
    end

    rule(:var_part) do
      spaced("VARIABLES") >> curly(var_types)
    end

    rule(:var_types) do
      with_separator(var_type, ",")
    end

    rule(:var_type) { object_identifier }

    rule(:descr_part) do
      spaced("DESCRIPTION") >> text
    end

    rule(:object_type_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("OBJECT-TYPE").as(:type) } >>
        spaced { syntax_part }.maybe >>
        spaced { units_part }.maybe >>
        spaced { max_access_part }.maybe >>
        (spaced("STATUS") >> spaced { status }).maybe >>
        spaced { description_clause }.maybe >>
        spaced { refer_part }.maybe >>
        spaced { index_part }.maybe >>
        spaced { mib_index }.maybe >>
        spaced { def_val_part }.maybe >>
        colon_colon_part >> curly(object_identifier.as(:value))
    end

    rule(:object_identity_clause) do
      spaced { lowercase_identifier.as(:name) } >>
        spaced { str("OBJECT-IDENTITY").as(:type) } >>
        spaced("STATUS") >> spaced { status } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { refer_part }.maybe >>
        colon_colon_part >> curly(object_identifier)
    end

    rule(:units_part) do
      spaced("UNITS") >> text.as(:units)
    end

    rule(:max_access_part) do
      spaced("MAX-ACCESS") >> access | spaced("ACCESS") >> access
    end

    rule(:access) { lowercase_identifier }

    rule(:description_clause) do
      spaced("DESCRIPTION") >> text
    end

    rule(:index_part) do
      spaced("AUGMENTS") >> curly(entry)
    end

    rule(:mib_index) do
      spaced("INDEX") >> curly(index_types)
    end

    rule(:def_val_part) do
      spaced("DEFVAL") >> curly(valueof_simple_syntax)
    end

    rule(:valueof_simple_syntax) do
      value | lowercase_identifier | text | curly(object_identifiers_defval)
    end

    rule(:object_identifiers_defval) do
      with_separator(object_identifier_defval)
    end

    rule(:object_identifier_defval) do
      spaced { lowercase_identifier } >> bracketed(number) |
        number
    end

    rule(:index_types) do
      with_separator(index_type, ",")
    end

    rule(:index_type) do
      spaced("IMPLIED") >> idx | idx
    end

    rule(:idx) do
      object_identifier
    end

    rule(:entry) do
      object_identifier
    end

    rule(:value_declaration) do
      spaced { fuzzy_lowercase_identifier.as(:name) } >>
        spaced { str("OBJECT IDENTIFIER").as(:type) } >>
        colon_colon_part >> curly(object_identifier.as(:value))
    end

    rule(:fuzzy_lowercase_identifier) do
      lowercase_identifier | uppercase_identifier
    end

    rule(:object_identifier) do
      sub_identifiers
    end

    rule(:sub_identifiers) do
      with_separator(sub_identifier, space_in_line.repeat)
    end

    rule(:sub_identifier) do
      fuzzy_lowercase_identifier |
        number |
        spaced { lowercase_identifier } >> bracketed(number)
    end

    rule(:type_declaration) do
      spaced { type_name.as(:vartype) } >> colon_colon_part >> type_declaration_rhs
    end

    rule(:type_name) do
      uppercase_identifier | type_smi
    end

    rule(:type_smi) do
      type_smi_and_sppi | type_smi_only
    end

    rule(:type_declaration_rhs) do
      spaced { choice_clause } |
        spaced { str("TEXTUAL-CONVENTION") } >>
        spaced { display_part }.maybe >>
        spaced("STATUS") >> spaced { status } >>
        spaced("DESCRIPTION") >> spaced { text } >>
        spaced { refer_part }.maybe >>
        spaced("SYNTAX") >> syntax |
        syntax
    end

    rule(:refer_part) do
      spaced("REFERENCE") >> text
    end

    rule(:choice_clause) do
      # Ignoring choice syntax
      spaced { str("CHOICE").as(:type) } >> curly(match("[^\}]").repeat)
    end

    rule(:syntax) do
      object_syntax | spaced("BITS").as(:type) >> curly(named_bits)
    end

    rule(:display_part) do
      spaced("DISPLAY-HINT") >> text
    end

    rule(:named_bits) do
      with_separator(named_bit, ",")
    end

    rule(:named_bit) do
      spaced { lowercase_identifier } >> bracketed(number)
    end

    rule(:object_syntax) do
      conceptual_table |
        entry_type |
        simple_syntax |
        application_syntax |
        type_tag >> simple_syntax |
        row.as(:value)
    end

    rule(:simple_syntax) do
      spaced { str("INTEGER").as(:type) } >> (integer_subtype | enum_spec).maybe |
        spaced { str("Integer32").as(:type) >> space } >> integer_subtype.maybe |
        spaced { str("OCTET STRING").as(:type) } >> octetstring_subtype.maybe |
        spaced { str("OBJECT IDENTIFIER").as(:type) } >> any_subtype |
        spaced { uppercase_identifier.as(:type) } >> (integer_subtype | enum_spec | octetstring_subtype)
    end

    rule(:application_syntax) do
      spaced { str("IpAddress").as(:type) >> space } >> any_subtype |
        spaced { str("NetworkAddress").as(:type) >> space } >> any_subtype |
        spaced { str("Counter32").as(:type) >> space } >> integer_subtype.maybe |
        spaced { str("Gauge32").as(:type) >> space } >> integer_subtype.maybe |
        spaced { str("Unsigned32").as(:type) >> space } >> integer_subtype.maybe |
        spaced { str("TimeTicks").as(:type) >> space } >> any_subtype |
        spaced { str("Opaque").as(:type) >> space } >> octetstring_subtype.maybe |
        spaced { str("Counter64").as(:type) >> space } >> integer_subtype.maybe
    end

    rule(:conceptual_table) do
      spaced { str("SEQUENCE OF").as(:type) } >> row.as(:value)
    end

    rule(:entry_type) do
      spaced { str("SEQUENCE").as(:type) } >> curly(sequence_items)
    end

    rule(:type_tag) do
      spaced { square_bracketed(spaced("APPLICATION") >> number.as(:application_type)) } >> spaced("IMPLICIT") |
        spaced { square_bracketed(spaced("UNIVERSAL") >> number.as(:universal_type)) } >> spaced("IMPLICIT")
    end

    rule(:sequence_items) do
      with_separator(sequence_item, ",")
    end

    rule(:sequence_item) do
      spaced { lowercase_identifier } >> spaced { sequence_syntax }
    end

    rule(:sequence_syntax) do
      str("BITS") |
        sequence_object_syntax |
        spaced { uppercase_identifier } >> any_subtype
    end

    rule(:sequence_object_syntax) do
      sequence_simple_syntax | sequence_application_syntax
    end

    rule(:sequence_simple_syntax) do
      spaced("INTEGER") >> any_subtype |
        spaced("Integer32") >> any_subtype |
        spaced("OCTET STRING") >> any_subtype |
        spaced("OBJECT IDENTIFIER") >> any_subtype
    end

    rule(:sequence_application_syntax) do
      spaced { str("IpAddress") >> space } >> any_subtype |
        spaced { str("COUNTER32") } >> any_subtype |
        spaced { str("Gauge32") >> space } >> any_subtype |
        spaced { str("Unsigned32") >> space } >> any_subtype |
        spaced { str("TimeTicks") >> space } >> any_subtype |
        str("Opaque") |
        spaced { str("Counter64") >> space } >> any_subtype
    end

    rule(:row) { uppercase_identifier }

    rule(:integer_subtype) { bracketed(ranges) }

    rule(:octetstring_subtype) do
      bracketed(spaced("SIZE") >> bracketed(ranges))
    end

    rule(:any_subtype) do
      (integer_subtype | octetstring_subtype | enum_spec).maybe
    end

    rule(:enum_spec) { curly(enum_items) }

    rule(:enum_items) do
      with_separator(enum_item.as(:enum), ",")
    end

    rule(:enum_item) do
      fuzzy_lowercase_identifier.as(:name) >> space.repeat >> bracketed(number.as(:value))
    end

    rule(:ranges) do
      with_separator(range.as(:range), "|")
    end

    rule(:range) do
      value.as(:min) >> space.repeat >> (str("..") >> space.repeat >> value.as(:max)).maybe
    end

    rule(:value) do
      number | hexstring | binstring
    end

    rule(:status) { lowercase_identifier }

    rule(:uppercase_identifier) do
      match("[A-Z]") >> match("[A-Za-z0-9\-]").repeat
    end

    rule(:lowercase_identifier) do
      match("[a-z]") >> match("[A-Za-z0-9\-]").repeat
    end

    rule(:type_smi_and_sppi) do
      str("IpAddress") | str("TimeTicks") | str("Opaque") | str("Integer32") | str("Unsigned32")
    end

    rule(:type_smi_only) do
      str("Counter") | str("Gauge32") | str("Counter64")
    end

    rule(:colon_colon_part) { spaced("::=") }

    rule(:space_in_line) { match('[ \t]').repeat(1) }
    rule(:cr) { match("\n") }
    rule(:space) do
      # this rule match all not important text
      (match('[ \t\r\n]') | comment_line).repeat(1)
    end

    rule(:comment_line) do
      (match('\-\-') >> match('[^\n]').repeat >> match('\n'))
    end

    rule(:space?) { space.maybe }
    rule(:digit) { match["0-9"] }
    rule(:hexchar) { match("[0-9a-fA-F]") }
    rule(:empty) { str("") }
    rule(:number) do
      (
        str("-").maybe >> (
          str("0") | (match("[1-9]") >> digit.repeat)
        ) >> (
          str(".") >> digit.repeat(1)
        ).maybe >> (
          match("[eE]") >> (str("+") | str("-")).maybe >> digit.repeat(1)
        ).maybe
      ).repeat(1)
    end

    rule(:hexstring) do
      str("'") >> hexchar.repeat >> str("'") >> match("[hH]")
    end

    rule(:binstring) do
      str("'") >> match["0-1"].repeat >> str("'")
    end

    rule(:text) do
      str('"') >> (
        str('\\') >> any | str('"').absent? >> any
      ).repeat >> str('"')
    end
  end
end
