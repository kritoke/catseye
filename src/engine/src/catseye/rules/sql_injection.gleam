import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{type TaintDB, build_finding_flow, is_suspect}
import gleam/list
import gleam/string

fn is_sql_call(name: String) -> Bool {
  list.any(
    [
      "DB.exec", "DB.query", "database.query", "connection.exec",
      "connection.query",
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
  |> list.filter(fn(n) { n.node_type == Call && is_sql_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    Finding(
      rule: "SQLInjection",
      severity: "Critical",
      file: n.file,
      line: n.line,
      message: "Potential SQL injection via "
        <> n.name
        <> ". User input may flow into a SQL query. Use parameterized queries.",
      flow: build_finding_flow(db, n),
    )
  })
}
