import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{
  type TaintDB, build_finding_flow, is_suspect, var_names_from_args,
}
import gleam/list
import gleam/string

fn is_file_call(name: String) -> Bool {
  list.any(
    [
      "File.read",
      "File.write",
      "File.open",
      "Dir.glob",
      "Dir.entries",
      "file.read",
      "file.write",
      "simplifile.read",
      "simplifile.write",
    ],
    fn(p) { string.starts_with(name, p) },
  )
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_file_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    let vars = var_names_from_args(n.args)
    Finding(
      rule: "PathTraversal",
      severity: "High",
      file: n.file,
      line: n.line,
      message: "Potential path traversal via "
        <> n.name
        <> " with variable argument(s): "
        <> vars
        <> ".",
      flow: build_finding_flow(db, n),
    )
  })
}
