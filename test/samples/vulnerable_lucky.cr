# test/samples/vulnerable_lucky.cr
# Simulates a Lucky (Crystal web framework) controller with real vulnerabilities

# Lucky-style params handling
class PostsController < BaseAction
  # SSRF: user-controlled URL flows into HTTP client
  def fetch_preview(params : Hash(String, String))
    url = params["preview_url"]
    response = HTTP::Client.get(url)
    render_text(response.body)
  end

  # Path traversal: user input in file path
  def serve_upload(params : Hash(String, String))
    filename = params["file"]
    content = File.read("uploads/#{filename}")
    send_file(content)
  end

  # Command injection: user input in shell command
  def generate_pdf(params : Hash(String, String))
    html_file = params["html"]
    system("wkhtmltopdf #{html_file} output.pdf")
  end

  # SQL injection: user input in raw query
  def search_posts(params : Hash(String, String))
    query = params["q"]
    results = AppDatabase.query("SELECT * FROM posts WHERE title LIKE '%#{query}%'")
    render_json(results)
  end

  # SAFE: hardcoded URL (should NOT flag)
  def fetch_about_page
    response = HTTP::Client.get("https://example.com/about")
    render_text(response.body)
  end

  # SAFE: validated/sanitized input (should NOT flag)
  def safe_fetch(params : Hash(String, String))
    url = URI.encode(params["url"])
    safe_url = URI.parse(url)
    HTTP::Client.get(safe_url)
  end

  # SAFE: parameterized query (should NOT flag)
  def safe_search(params : Hash(String, String))
    query = params["q"]
    results = AppDatabase.query("SELECT * FROM posts WHERE title LIKE ?", query)
    render_json(results)
  end
end
