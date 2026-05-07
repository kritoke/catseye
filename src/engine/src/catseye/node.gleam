//// Catseye Node Type and JSON Decoding
//// Defines the Security Node type that matches the bridge JSON schema.
//// Uses Erlang FFI for JSON parsing (no external Gleam deps needed).

import gleam/list

// ── Types ──────────────────────────────────────────────────────────────

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
  Arg(arg_type: ArgType, value: String)
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

pub type Finding {
  Finding(
    rule: String,
    severity: String,
    file: String,
    line: Int,
    message: String,
  )
}

// ── Erlang FFI for JSON ────────────────────────────────────────────────

/// Decode a JSON string into a raw Erlang term, then parse in Gleam.
@external(erlang, "catseye_engine_ffi", "decode_json")
pub fn decode_json(json_string: String) -> Result(List(Node), Nil)

/// Encode a list of findings to JSON string.
@external(erlang, "catseye_engine_ffi", "encode_findings")
pub fn encode_findings(findings: List(Finding)) -> String

// ── Node helpers ───────────────────────────────────────────────────────

/// Check if any argument is a variable (not a literal)
pub fn has_var_args(node: Node) -> Bool {
  list.any(node.args, fn(a) { a.arg_type == ArgVar })
}

/// Check if all arguments are literals
pub fn all_args_literal(node: Node) -> Bool {
  list.all(node.args, fn(a) { a.arg_type == ArgLiteral })
}
