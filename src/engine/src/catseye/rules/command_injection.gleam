//// Command injection detection rule.
//// Flags system/exec calls with variable/tainted arguments.

import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{is_suspect}
import gleam/list
import gleam/string

fn is_shell_call(name: String) -> Bool {
  // Database calls are NOT shell commands — whitelist them
  let db_patterns = [
    "db.exec", "db.query", "db.scalar", "db.query_one", "db.query_all",
    "db.execute",
    // Crystal DB driver patterns
    ".exec(", ".query(",
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
          // Crystal
          "system", "Process.run", "``",
          // Gleam/Erlang
          "os.command", "os.cmd", "shell.cmd", "cmd.run",
        ],
        fn(p) { string.contains(name, p) },
      )
  }
}

pub fn check(nodes: List(Node), tainted: List(String)) -> List(Finding) {
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
    )
  })
}
