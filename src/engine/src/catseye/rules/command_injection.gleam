import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{type TaintDB, build_finding_flow, is_suspect}
import gleam/list
import gleam/string

/// Shell execution sinks — commands run through a system shell
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
          // Crystal
          "system", "Process.run", "``",
          // Gleam/Erlang
          "os.command", "os.cmd", "shell.cmd", "cmd.run",
          // Erlang specific
          "erlexec.Shell", ":os.cmd",
        ],
        fn(p) { string.contains(name, p) },
      )
  }
}

/// Environment variable setters — tainted data in ENV[]= is dangerous
fn is_env_setter(name: String) -> Bool {
  string.contains(name, "ENV[]=")
  || string.contains(name, "ENV.[]=")
  || string.contains(name, "putenv")
  || string.contains(name, "os.setenv")
  || string.contains(name, "os.putenv")
  || string.contains(name, "system.putenv")
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  // B1: Command injection via shell calls
  let cmdi_findings =
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

  // B2/E: Environment variable injection
  let env_findings =
    nodes
    |> list.filter(fn(n) { n.node_type == Call && is_env_setter(n.name) })
    |> list.filter(fn(n) { is_suspect(n, tainted) })
    |> list.map(fn(n) {
      Finding(
        rule: "EnvInjection",
        severity: "High",
        file: n.file,
        line: n.line,
        message: "Potential environment injection via "
          <> n.name
          <> ". User input may control environment variables (PATH, LD_PRELOAD, etc.). "
          <> "Validate and whitelist allowed variable names and values.",
        flow: build_finding_flow(db, n),
      )
    })

  list.append(cmdi_findings, env_findings)
}
