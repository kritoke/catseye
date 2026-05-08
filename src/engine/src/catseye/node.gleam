import gleam/list

pub type NodeType {
  Call
  Assign
  Def
  Var
  Literal
}

pub type ArgType {
  ArgVar
  ArgLiteral
  ArgCall
  ArgUnknown
}

pub type Arg {
  Arg(arg_type: ArgType, value: String, field: String)
}

pub type Node {
  Node(
    node_type: NodeType,
    name: String,
    args: List(Arg),
    line: Int,
    taint: Bool,
    file: String,
  )
}

pub type FlowStep {
  FlowStep(file: String, line: Int, message: String)
}

pub type Finding {
  Finding(
    rule: String,
    severity: String,
    file: String,
    line: Int,
    message: String,
    flow: List(FlowStep),
  )
}

@external(erlang, "catseye_engine_ffi", "decode_json")
pub fn decode_json(json_string: String) -> Result(List(Node), Nil)

@external(erlang, "catseye_engine_ffi", "encode_findings")
pub fn encode_findings(findings: List(Finding)) -> String

pub fn has_var_args(node: Node) -> Bool {
  list.any(node.args, fn(a) { a.arg_type == ArgVar })
}

pub fn all_args_literal(node: Node) -> Bool {
  list.all(node.args, fn(a) { a.arg_type == ArgLiteral })
}

/// Check if all args are either literal OR sanitized calls
pub fn all_args_safe(node: Node, sanitizers: List(String)) -> Bool {
  list.all(node.args, fn(a) {
    case a.arg_type {
      ArgLiteral -> True
      ArgCall -> list.any(sanitizers, fn(s) { string_starts_with(a.value, s) })
      _ -> False
    }
  })
}

fn string_starts_with(haystack: String, needle: String) -> Bool {
  case needle {
    "" -> True
    _ ->
      case haystack {
        "" -> needle == ""
        _ ->
          case string_slice(haystack, 0, string_length(needle)) == needle {
            True -> True
            False -> False
          }
      }
  }
}

@external(erlang, "string", "slice")
fn string_slice(s: String, start: Int, len: Int) -> String

@external(erlang, "string", "length")
fn string_length(s: String) -> Int
