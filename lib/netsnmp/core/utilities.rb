module NETSNMP::Core

  def self.version
    LibSNMP.netsnmp_get_version
  end


  # Do not support versions lower than 5.5, as they're mostly buggy.
  if version < "5.5"
    raise LoadError, "The netsnmp version #{version} is incompatible with this version of ffi-netsnmp-core"
  end

end
