require 'netsnmp'
module NETSNMP
  module EM
    class Client < ::NETSNMP::Client

      def initialize(*args)
        @session = EM::Session.new(*args)
        super
      end

    end

    class Session < ::NETSNMP::Session
      module Watcher
        def initialize(client, deferable)
          @client = client
          @deferable = deferable
          @is_watching = true
        end

        def notify_readable
          detach
          begin
            operation = nil
            @client.__send__ :async_read
            result = @client.__send__ :handle_response
          rescue => e
            @deferable.fail(e)
          else
            @deferable.succeed(result)
          end
        end

        def watching?
          @is_watching
        end

        def unbind
          @is_watching = false
        end
      end

      def send(pdu)
        if ::EM.reactor_running?
          write(pdu)
          deferable = ::EM::DefaultDeferrable.new
          watch = ::EM.watch(transport.fileno, Watcher, self, deferable)
          watch.notify_readable = true
          ::EM::Synchrony.sync deferable
        else
          super
        end
      end
    end
  end
end
