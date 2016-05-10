require 'socket'
module SNMP
  module Client
    # RFC 2571

    def bang(options={})
      hostname, port = options.values_at(:hostname, :port)

      sock = UDPSocket.new
      sock.bind(hostname, port)

    end

  end
end
