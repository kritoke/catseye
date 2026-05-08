import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{
  type TaintDB, build_finding_flow, is_suspect, var_names_from_args,
}
import gleam/list
import gleam/string

fn is_file_call(name: String) -> Bool {
  list.any(
    [
      "File.read", "File.write", "File.open", "File.delete", "Dir.glob",
      "Dir.entries", "Dir.mkdir", "file.read", "file.write", "file.delete",
      "simplifile.read", "simplifile.write", "simplifile.delete",
    ],
    fn(p) { string.starts_with(name, p) },
  )
}

/// File.join with user-controlled input is a path traversal risk
fn is_file_join(name: String) -> Bool {
  string.contains(name, "File.join")
  || string.contains(name, "Path.join")
  || string.contains(name, "path.join")
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  // C1: Direct file ops with tainted paths
  let file_findings =
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
          <> ". User input may control file paths. Validate and sanitize path components.",
        flow: build_finding_flow(db, n),
      )
    })

  // C2: File.join / Path.join with tainted input (no .. sanitization)
  let join_findings =
    nodes
    |> list.filter(fn(n) { n.node_type == Call && is_file_join(n.name) })
    |> list.filter(fn(n) { is_suspect(n, tainted) })
    |> list.map(fn(n) {
      let vars = var_names_from_args(n.args)
      Finding(
        rule: "PathTraversal",
        severity: "Medium",
        file: n.file,
        line: n.line,
        message: "Potential path traversal via "
          <> n.name
          <> " with variable argument(s): "
          <> vars
          <> ". Ensure user input is sanitized for '..' sequences before joining paths.",
        flow: build_finding_flow(db, n),
      )
    })

  list.append(file_findings, join_findings)
}
