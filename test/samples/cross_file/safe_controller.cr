require "./safe_helpers"

def handle_safe_request
  # SAFE: get_clean_link returns a hardcoded constant
  dest = get_clean_link()
  HTTP::Client.get(dest)
end
