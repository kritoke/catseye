# test/samples/safe_timeouts.cr
# Safe Crystal HTTP patterns — should produce 0 MissingTimeout findings

require "http/client"

class SafeHTTP
  # Pattern 1: timeout set via property assignment
  def fetch_with_explicit_timeout(url : String)
    client = HTTP::Client.new(URI.parse(url))
    client.read_timeout = 30.seconds
    client.write_timeout = 10.seconds
    client.connect_timeout = 10.seconds
    client.get("/")
  end

  # Pattern 2: timeout set via helper method
  def fetch_with_helper(url : String)
    client = HTTP::Client.new(URI.parse(url))
    apply_default_timeouts(client)
    client.get("/")
  end

  private def apply_default_timeouts(client : HTTP::Client)
    client.read_timeout = 30.seconds
    client.write_timeout = 10.seconds
    client.connect_timeout = 10.seconds
  end
end
