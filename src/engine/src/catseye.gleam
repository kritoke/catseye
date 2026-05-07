//// Catseye Logic Engine — Entry Point
////
//// Reads a JSON array of security nodes from stdin,
//// runs all vulnerability detection rules, and outputs findings as JSON.

import gleam/io
import catseye/node.{decode_json, encode_findings}
import catseye/ssrf

// ── Erlang FFI for stdin ───────────────────────────────────────────────

@external(erlang, "catseye_engine_ffi", "read_stdin")
fn read_stdin() -> Result(String, Nil)

// ── Main ───────────────────────────────────────────────────────────────

pub fn main() {
  let assert Ok(json_string) = read_stdin()

  case decode_json(json_string) {
    Ok(nodes) -> {
      let findings = ssrf.run_all_rules(nodes)
      io.println(encode_findings(findings))
    }
    Error(_) -> {
      io.println("[]")
    }
  }
}
