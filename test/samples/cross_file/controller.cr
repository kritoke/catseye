require "./helpers"

def handle_request(params)
  # Cross-file: target = get_user_link(params) should be tainted
  # because get_user_link returns params["target"] from helpers.cr
  dest = get_user_link(params)
  HTTP::Client.get(dest)
end
