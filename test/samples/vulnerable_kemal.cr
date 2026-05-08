# test/samples/vulnerable_kemal.cr
# Simulates a Kemal (Crystal web framework) app with real vulnerabilities

require "kemal"

# SSRF via Kemal params
get "/preview" do |env|
  url = env.params.query["url"]
  response = HTTP::Client.get(url)
  response.body
end

# Path traversal via Kemal params
get "/download" do |env|
  filename = env.params.query["file"]
  File.read("./public/#{filename}")
end

# Command injection via form params
post "/convert" do |env|
  input_file = env.params.body["input"]
  system("ffmpeg -i #{input_file} output.mp4")
end

# SAFE: static content (should NOT flag)
get "/about" do |env|
  "About page"
end

# SAFE: sanitized input (should NOT flag)
get "/safe_download" do |env|
  filename = Path.basename(env.params.query["file"])
  File.read("./public/#{filename}")
end
