# test/samples/vulnerable.cr
# Intentionally vulnerable Crystal code for testing Catseye

require "http/client"

class VulnerableApp
  # SSRF: user input flows into HTTP::Client.get
  def fetch_url(user_url : String)
    # line 9: assign of user-controlled value
    url = user_url
    # line 11: HTTP call with variable argument → SSRF
    response = HTTP::Client.get(url)
    response.body
  end

  # SSRF via params hash
  def handle_request(params : Hash(String, String))
    target = params["url"]
    HTTP::Client.get(target)
  end

  # Safe: hardcoded URL (should NOT flag)
  def fetch_homepage
    HTTP::Client.get("https://example.com")
  end

  # Command injection via system call
  def run_git_command(user_input : String)
    repo = user_input
    system("git clone #{repo}")
  end
end
