import catseye/node.{decode_json, encode_findings, type Node}
import catseye/rules
import catseye/rules/taint
import gleam/io
import gleam/list
import gleam/string

@external(erlang, "catseye_engine_ffi", "read_stdin")
fn read_stdin() -> Result(String, Nil)

/// Parse a config object from the input JSON.
/// Config format: {"nodes": [...], "config": {"extra_sources": [...], "extra_sanitizers": [...]}}
/// Legacy format: [...] (just nodes array) is also supported.
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
  // Try new format first, fall back to legacy
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
      // Legacy: try decoding as plain node array
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
  // Check if JSON starts with '{' (object) vs '[' (array)
  case string.starts_with(string.trim(json_string), "{") {
    False -> Error(Nil)
    True -> decode_input(json_string)
  }
}

fn has_config(config: EngineConfig) -> Bool {
  list.length(config.extra_sources) > 0
  || list.length(config.extra_sanitizers) > 0
}
