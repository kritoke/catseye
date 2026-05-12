# Test: Concurrency trap patterns

# 1. Channel opened but never sent to (Muted Pack)
class BrokenWorker
  @channel = Channel(String).new

  def start
    spawn do
      # Never sends to channel — receiver waits forever
      result = do_work
      # Oops, forgot: @channel.send(result)
    end
  end

  def wait_for_result
    @channel.receive # Blocks forever
  end
end

# 2. Channel closed before receive (Dead Letter)
class PrematureClose
  def process
    ch = Channel(String).new
    spawn do
      ch.send("data")
    end
    ch.close # Close before receive — sender gets ClosedError
    ch.receive
  end
end

# 3. Clean pattern (should NOT be flagged)
class CleanWorker
  @channel = Channel(String).new

  def start
    spawn do
      result = do_work
      @channel.send(result)
    end
  end

  def wait_for_result
    @channel.receive
  end
end

private def do_work
  "done"
end
