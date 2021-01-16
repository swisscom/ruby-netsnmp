# frozen_string_literal: true

require_relative "mib/parser"

module NETSNMP
  module MIB
    using IsNumericExtensions

    OIDREGEX = /^[\d\.]*$/

    module_function

    MIBDIRS = ENV.fetch("MIBDIRS", File.join("/usr", "share", "snmp", "mibs")).split(":")
    PARSER = Parser.new
    @parser_mutex = Mutex.new
    @modules_loaded = []
    @object_identifiers = {}

    # Translates na identifier, such as "sysDescr", into an OID
    def oid(identifier)
      prefix, *suffix = case identifier
                        when Array
                          identifier
                        else
                          identifier.split(".", 2)
                        end

      # early exit if it's an OID already
      unless prefix.integer?
        load_defaults
        # load module if need be
        idx = prefix.index("::")
        if idx
          mod = prefix[0..(idx - 1)]
          type = prefix[(idx + 2)..-1]
          return unless load(mod)
        else
          type = prefix
        end

        return if type.nil? || type.empty?

        prefix = @object_identifiers[type] ||
                 raise(Error, "can't convert #{type} to OID")

      end

      [prefix, *suffix].join(".")
    end

    # This is a helper function, do not rely on this functionality in future
    # versions
    def identifier(oid)
      @object_identifiers.select do |_, full_oid|
        full_oid.start_with?(oid)
      end
    end

    #
    # Loads a MIB. Can be called multiple times, as it'll load it once.
    #
    # Accepts the MIB name in several ways:
    #
    #     MIB.load("SNMPv2-MIB")
    #     MIB.load("SNMPv2-MIB.txt")
    #     MIB.load("/path/to/SNMPv2-MIB.txt")
    #
    def load(mod)
      unless File.file?(mod)
        moddir = nil
        MIBDIRS.each do |mibdir|
          if File.exist?(File.join(mibdir, mod))
            moddir = File.join(mibdir, mod)
            break
          elsif File.extname(mod).empty? && File.exist?(File.join(mibdir, "#{mod}.txt"))
            moddir = File.join(mibdir, "#{mod}.txt")
            break
          end
        end
        return false unless moddir
        mod = moddir
      end
      return true if @modules_loaded.include?(mod)
      do_load(mod)
      @modules_loaded << mod
      true
    end

    TYPES = ["OBJECT-TYPE", "OBJECT IDENTIFIER", "MODULE-IDENTITY"].freeze

    STATIC_MIB_TO_OID = {
      "iso" => "1"
    }.freeze

    #
    # Loads the MIB all the time, where +mod+ is the absolute path to the MIB.
    #
    def do_load(mod)
      data = @parser_mutex.synchronize { PARSER.parse(File.read(mod)) }

      imports = load_imports(data)

      data[:declarations].each_with_object(@object_identifiers) do |dec, types|
        next unless TYPES.include?(dec[:type])

        oid = String(dec[:value]).split(/ +/).flat_map do |cp|
          if cp.integer?
            cp
          else
            STATIC_MIB_TO_OID[cp] || @object_identifiers[cp] || begin
              imported_mod, = imports.find do |_, identifiers|
                identifiers.include?(cp)
              end

              raise Error, "didn't find a module to import \"#{cp}\" from" unless imported_mod

              load(imported_mod)

              @object_identifiers[cp]
            end
          end
        end.join(".")

        types[String(dec[:name])] = oid
      end
    end

    #
    # Reformats the import lists into an hash indexed by module name, to a list of
    # imported names
    #
    def load_imports(data)
      return unless data[:imports]

      data[:imports].each_with_object({}) do |import, imp|
        imp[String(import[:name])] = case import[:ids]
                                     when Hash
                                       [String(import[:ids][:name])]
                                     else
                                       import[:ids].map { |id| String(id[:name]) }
                                     end
      end
    end

    def load_defaults
      # loading the defaults MIBS
      load("SNMPv2-MIB")
      load("IF-MIB")
    end
  end
end
