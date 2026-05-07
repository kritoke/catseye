import catseye/node.{decode_json, encode_findings}
import catseye/rules
import gleam/io

@external(erlang, "catseye_engine_ffi", "read_stdin")
fn read_stdin() -> Result(String, Nil)

pub fn main() {
  let assert Ok(json_string) = read_stdin()
  case decode_json(json_string) {
    Ok(nodes) -> {
      let findings = rules.run_all_rules(nodes)
      io.println(encode_findings(findings))
    }
    Error(_) -> io.println("[]")
  }
}
