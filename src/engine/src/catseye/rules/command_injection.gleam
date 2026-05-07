import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{type TaintDB, build_finding_flow, is_suspect}
import gleam/list
import gleam/string

fn is_shell_call(name: String) -> Bool {
  let db_patterns = [
    "db.exec", "db.query", "db.scalar", "db.query_one", "db.query_all",
    "db.execute",
  ]
  let is_db =
    list.any(db_patterns, fn(p) { string.contains(name, p) })
    || string.contains(name, "database.exec")
    || string.contains(name, "database.query")
  case is_db {
    True -> False
    False ->
      list.any(
        [
          "system", "Process.run", "``", "os.command", "os.cmd", "shell.cmd",
          "cmd.run",
        ],
        fn(p) { string.contains(name, p) },
      )
  }
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_shell_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    Finding(
      rule: "CommandInjection",
      severity: "Critical",
      file: n.file,
      line: n.line,
      message: "Potential command injection via "
        <> n.name
        <> ". User input may flow into a shell command.",
      flow: build_finding_flow(db, n),
    )
  })
}
