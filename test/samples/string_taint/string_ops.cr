# Test case for string operation taint propagation
# Taint should flow through string operations

require "uri"

# Test 1: upcase on tainted string
def transform_url(url)
  upcased = url.upcase
  HTTP::Client.get(upcased)  # Should flag - upcased inherits taint from url
end

# Test 2: gsub on tainted string  
def sanitize_url(url)
  cleaned = url.gsub("'", "''")
  HTTP::Client.get(cleaned)  # Should flag - cleaned inherits taint
end

# Test 3: split - get first segment
def get_host(url)
  parts = url.split("/")
  first = parts[0]
  HTTP::Client.get(first)  # Should flag - first inherits taint via split
end

# Test 4: strip on tainted
def clean_param(input)
  trimmed = input.strip
  HTTP::Client.get(trimmed)  # Should flag
end

# Test 5: Chain of string ops
def multi_transform(url)
  step1 = url.upcase
  step2 = step1.strip
  HTTP::Client.get(step2)  # Should flag
end
