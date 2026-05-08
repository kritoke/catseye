import catseye/node.{type Node, decode_json, encode_findings}
import catseye/rules
import gleam/io
import gleam/string

@external(erlang, "catseye_engine_ffi", "read_stdin")
fn read_stdin() -> Result(String, Nil)

/// Decode the config-aware input format from JSON.
/// Erlang returns: {input, List(Node), {engine_config, List(Bin), List(Bin)}}
@external(erlang, "catseye_engine_ffi", "decode_input")
fn decode_input(json_string: String) -> Result(Input, Nil)

pub type Input {
  Input(nodes: List(Node), config: EngineConfig)
}

pub type EngineConfig {
  EngineConfig(extra_sources: List(String), extra_sanitizers: List(String))
}

pub fn main() {
  let assert Ok(json_string) = read_stdin()
  // Try new config-aware format first, fall back to legacy plain array
  case try_decode_input(json_string) {
    Ok(input) -> {
      let findings = case has_config(input.config) {
        True ->
          rules.run_all_rules_with_config(
            input.nodes,
            input.config.extra_sources,
            input.config.extra_sanitizers,
          )
        False -> rules.run_all_rules(input.nodes)
      }
      io.println(encode_findings(findings))
    }
    Error(Nil) ->
      // Legacy: plain node array
      case decode_json(json_string) {
        Ok(nodes) -> {
          let findings = rules.run_all_rules(nodes)
          io.println(encode_findings(findings))
        }
        Error(_) -> io.println("[]")
      }
  }
}

fn try_decode_input(json_string: String) -> Result(Input, Nil) {
  case string.starts_with(string.trim(json_string), "{") {
    False -> Error(Nil)
    True -> decode_input(json_string)
  }
}

fn has_config(config: EngineConfig) -> Bool {
  config.extra_sources != [] || config.extra_sanitizers != []
}
