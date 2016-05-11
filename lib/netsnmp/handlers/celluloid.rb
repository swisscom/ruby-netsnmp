require 'netsnmp'
module NETSNMP
  module Celluloid 
    class Client < ::NETSNMP::Client

      def initialize(*args)
        @session = Celluloid::Session.new(*args)
        super
      end

    end

    class Session < ::NETSNMP::Session
      def wait_readable
        return super unless ::Celluloid::IO.evented?
        ::Celluloid::IO.wait_readable(transport)
        [[transport]]
      end

      def wait_writable
        return super unless ::Celluloid::IO.evented?
        ::Celluloid::IO.wait_writable(transport)
        [[],[transport]]
      end
    end
  end
end
