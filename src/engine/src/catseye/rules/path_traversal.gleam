//// Path traversal detection rule.
//// Flags File.read/Dir.glob calls with variable/tainted arguments.

import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{is_suspect, var_names_from_args}
import gleam/list
import gleam/string

fn is_file_call(name: String) -> Bool {
  list.any(
    ["File.read", "File.write", "File.open", "Dir.glob", "Dir.entries"],
    fn(p) { string.starts_with(name, p) },
  )
}

pub fn check(nodes: List(Node), tainted: List(String)) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_file_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    Finding(
      rule: "PathTraversal",
      severity: "High",
      file: n.file,
      line: n.line,
      message: "Potential path traversal via "
        <> n.name
        <> " with variable argument(s): "
        <> var_names_from_args(n.args)
        <> ". User input may control file paths. Validate and sanitize path components.",
    )
  })
}
