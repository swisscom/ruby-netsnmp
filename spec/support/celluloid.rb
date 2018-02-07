# frozen_string_literal: true

# Copied from celluloid-io spec helpers
module CelluloidHelpers
  class WrapperActor
    include ::Celluloid::IO
    execute_block_on_receiver :wrap

    def wrap
      yield
    end
  end

  def with_wrapper_actor
    WrapperActor.new
  end

  def within_io_actor(&block)
    actor = WrapperActor.new
    actor.wrap(&block)
  ensure
    begin
      actor.terminate if actor.alive?
    rescue StandardError
      nil
    end
  end

  class Proxy < NETSNMP::Session::Transport
    MAXPDUSIZE = 0xffff + 1

    def initialize(host, port)
      @socket = Celluloid::IO::UDPSocket.new
      @socket.connect(host, port)
      @timeout = 2
    end

    def close
      @socket.close
    end

    private

    def wait(mode)
      Celluloid.timeout(@timeout) do
        @socket.__send__(mode)
      end
    rescue Celluloid::TaskTimeout
      raise Timeout::Error, "Timeout after #{@timeout} seconds"
    end
  end
end
