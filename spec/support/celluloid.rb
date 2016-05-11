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
    actor.terminate if actor.alive? rescue nil
  end

end
