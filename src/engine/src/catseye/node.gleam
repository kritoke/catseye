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
