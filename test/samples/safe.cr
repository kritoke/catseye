# test/samples/safe.cr
# Safe Crystal code — should produce zero findings

require "http/client"

class SafeApp
  # All URLs are hardcoded literals
  def fetch_homepage
    HTTP::Client.get("https://example.com")
  end

  def fetch_api
    response = HTTP::Client.get("https://api.example.com/v1/status")
    puts response.body
  end

  # No external calls at all
  def compute(x : Int32, y : Int32)
    x + y
  end
end
