// test/samples/vulnerable.gleam
// Intentionally vulnerable Gleam code

import gleam/io

pub fn fetch_user(url: String) {
  let target = url
  // SSRF: variable flows into HTTP call
  hackney.get(target)
}

pub fn handle_request(req: String) {
  // Tainted from request
  let body = request.get_body(req)
  hackney.post(body)
}

pub fn safe_fetch() {
  // Safe: hardcoded URL
  hackney.get("https://example.com")
  Nil
}

pub fn run_cmd(user_input: String) {
  let cmd = user_input
  os.command(cmd)
}
