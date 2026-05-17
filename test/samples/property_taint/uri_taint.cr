# Test case for URI property taint propagation
# Using known taint sources

require "uri"

# Test 1: Direct source to URI.parse to HTTP.get
# url is a known source -> gets seeded as tainted
# uri = URI.parse(url) -> uri properties inherit taint
# HTTP::Client.get(uri.request_target) -> flagged
def proxy_request(url)
  uri = URI.parse(url)
  HTTP::Client.get(uri.request_target)  # Should flag
end

# Test 2: Within a class with params
class ProxyController
  def handle_request
    url = params["url"]  # Known source (params["..."] returns tainted)
    uri = URI.parse(url)
    HTTP::Client.get(uri.request_target)  # Should flag
  end
end

# Test 3: Aliasing with a known source param
# link is NOT a known source, so we test aliasing via params
class Service
  def fetch_url(url_to_fetch)
    parsed = URI.parse(url_to_fetch)
    target = parsed  # alias - should also have tainted properties
    HTTP::Client.get(target.request_target)  # Should flag
  end
end