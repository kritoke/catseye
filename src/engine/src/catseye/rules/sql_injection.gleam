import catseye/node.{type Finding, type Node, ArgCall, Call, Finding}
import catseye/rules/taint.{type TaintDB, build_finding_flow, is_suspect}
import gleam/list
import gleam/string

fn is_sql_call(name: String) -> Bool {
  list.any(
    [
      "DB.exec", "DB.query", "DB.scalar", "database.query", "database.exec",
      "connection.exec", "connection.query",
    ],
    fn(p) { string.starts_with(name, p) },
  )
}

/// Check if a SQL call uses string interpolation instead of parameterized queries
fn has_sql_interpolation(node: Node) -> Bool {
  list.any(node.args, fn(a) {
    case a.arg_type {
      ArgCall -> string.contains(a.value, "<interpolation>")
      _ -> False
    }
  })
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_sql_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    let interp_msg = case has_sql_interpolation(n) {
      True ->
        " String interpolation detected — use parameterized queries (? placeholders) instead of #{...}."
      False -> ""
    }
    Finding(
      rule: "SQLInjection",
      severity: "Critical",
      file: n.file,
      line: n.line,
      message: "Potential SQL injection via "
        <> n.name
        <> ". User input may flow into a SQL query. Use parameterized queries."
        <> interp_msg,
      flow: build_finding_flow(db, n),
    )
  })
}
