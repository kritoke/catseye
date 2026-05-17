# User file - should inherit taint from source.cr
require "./source"

def process(url)
  # url comes from another file's tainted source
  HTTP::Client.get(url)  # Should flag - url is tainted via cross-file propagation
end
