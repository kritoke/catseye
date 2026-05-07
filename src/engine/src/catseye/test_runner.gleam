//// Catseye Engine test runner (no eunit dependency)
//// Run: cd src/engine && gleam run -m catseye/test_runner

import catseye/node.{
  type Arg, type Node, Arg, ArgCall, ArgLiteral, ArgVar, Assign, Call, Node,
}
import catseye/rules
import catseye/rules/command_injection
import catseye/rules/path_traversal
import catseye/rules/sql_injection
import catseye/rules/ssrf
import catseye/rules/taint
import gleam/int
import gleam/io
import gleam/list

// ── Helpers ────────────────────────────────────────────────────────────

fn node_(
  type_: node.NodeType,
  name: String,
  args: List(Arg),
  taint: Bool,
) -> Node {
  Node(
    node_type: type_,
    name: name,
    args: args,
    line: 1,
    taint: taint,
    file: "test.cr",
  )
}

fn arg_(type_: node.ArgType, value: String) -> Arg {
  Arg(arg_type: type_, value: value)
}

fn assert_eq(label: String, got: a, want: a) -> Bool {
  case got == want {
    True -> True
    False -> {
      io.println("  FAIL: " <> label)
      False
    }
  }
}

// ── Taint tracking ─────────────────────────────────────────────────────

fn taint_extracts_names() -> Bool {
  let nodes = [
    node_(Assign, "x", [arg_(ArgVar, "params")], True),
    node_(Assign, "y", [arg_(ArgLiteral, "safe")], False),
    node_(Assign, "z", [arg_(ArgVar, "gets")], True),
  ]
  let tainted = taint.build_tainted_vars(nodes)
  assert_eq("tainted count", list.length(tainted), 2)
  && assert_eq("tainted has x", list.contains(tainted, "x"), True)
  && assert_eq("tainted not y", list.contains(tainted, "y"), False)
}

// ── SSRF ───────────────────────────────────────────────────────────────

fn ssrf_flags_var() -> Bool {
  let nodes = [node_(Call, "HTTP::Client.get", [arg_(ArgVar, "url")], False)]
  let findings = ssrf.check(nodes, [])
  assert_eq("ssrf flags var", list.length(findings), 1)
}

fn ssrf_ignores_literal() -> Bool {
  let nodes = [
    node_(
      Call,
      "HTTP::Client.get",
      [arg_(ArgLiteral, "https://example.com")],
      False,
    ),
  ]
  let findings = ssrf.check(nodes, [])
  assert_eq("ssrf ignores literal", list.length(findings), 0)
}

fn ssrf_flags_tainted() -> Bool {
  let nodes = [
    node_(Assign, "target", [arg_(ArgVar, "params")], True),
    node_(Call, "HTTP::Client.get", [arg_(ArgVar, "target")], False),
  ]
  let tainted = taint.build_tainted_vars(nodes)
  let findings = ssrf.check(nodes, tainted)
  assert_eq("ssrf flags tainted", list.length(findings), 1)
}

fn ssrf_all_methods() -> Bool {
  let nodes =
    list.map(
      [
        "HTTP::Client.get",
        "HTTP::Client.post",
        "HTTP::Client.put",
        "HTTP::Client.delete",
      ],
      fn(m) { node_(Call, m, [arg_(ArgVar, "url")], False) },
    )
  let findings = ssrf.check(nodes, [])
  assert_eq("ssrf all methods", list.length(findings), 4)
}

fn ssrf_ignores_non_http() -> Bool {
  let nodes = [
    node_(Call, "puts", [arg_(ArgVar, "data")], False),
    node_(Call, "JSON.parse", [arg_(ArgVar, "input")], False),
  ]
  let findings = ssrf.check(nodes, [])
  assert_eq("ssrf ignores non-http", list.length(findings), 0)
}

// ── Command injection ──────────────────────────────────────────────────

fn cmdi_flags_system() -> Bool {
  let nodes = [node_(Call, "system", [arg_(ArgVar, "cmd")], False)]
  let findings = command_injection.check(nodes, [])
  assert_eq("cmdi flags system", list.length(findings), 1)
}

fn cmdi_flags_process_run() -> Bool {
  let nodes = [node_(Call, "Process.run", [arg_(ArgVar, "cmd")], False)]
  let findings = command_injection.check(nodes, [])
  assert_eq("cmdi flags Process.run", list.length(findings), 1)
}

fn cmdi_ignores_literal() -> Bool {
  let nodes = [node_(Call, "system", [arg_(ArgLiteral, "echo hello")], False)]
  let findings = command_injection.check(nodes, [])
  assert_eq("cmdi ignores literal", list.length(findings), 0)
}

// ── Path traversal ─────────────────────────────────────────────────────

fn pt_flags_file_read() -> Bool {
  let nodes = [node_(Call, "File.read", [arg_(ArgVar, "path")], False)]
  let findings = path_traversal.check(nodes, [])
  assert_eq("pt flags File.read", list.length(findings), 1)
}

fn pt_ignores_literal() -> Bool {
  let nodes = [
    node_(Call, "File.read", [arg_(ArgLiteral, "/etc/hostname")], False),
  ]
  let findings = path_traversal.check(nodes, [])
  assert_eq("pt ignores literal", list.length(findings), 0)
}

fn pt_flags_dir_glob() -> Bool {
  let nodes = [
    node_(Call, "Dir.glob", [arg_(ArgCall, "<interpolation>")], False),
  ]
  let findings = path_traversal.check(nodes, [])
  assert_eq("pt flags Dir.glob", list.length(findings), 1)
}

// ── SQL injection ──────────────────────────────────────────────────────

fn sqli_flags_db_query() -> Bool {
  let nodes = [node_(Call, "DB.query", [arg_(ArgVar, "sql")], False)]
  let findings = sql_injection.check(nodes, [])
  assert_eq("sqli flags DB.query", list.length(findings), 1)
}

fn sqli_ignores_literal() -> Bool {
  let nodes = [node_(Call, "DB.query", [arg_(ArgLiteral, "SELECT 1")], False)]
  let findings = sql_injection.check(nodes, [])
  assert_eq("sqli ignores literal", list.length(findings), 0)
}

// ── Integration ────────────────────────────────────────────────────────

fn run_all_combines() -> Bool {
  let nodes = [
    node_(Call, "HTTP::Client.get", [arg_(ArgVar, "url")], False),
    node_(Call, "system", [arg_(ArgVar, "cmd")], False),
    node_(Call, "File.read", [arg_(ArgVar, "path")], False),
    node_(Call, "DB.query", [arg_(ArgVar, "sql")], False),
  ]
  let findings = rules.run_all_rules(nodes)
  assert_eq("run_all combines all rules", list.length(findings), 4)
}

fn run_all_empty() -> Bool {
  let findings = rules.run_all_rules([])
  assert_eq("run_all empty", list.length(findings), 0)
}

// ── Runner ─────────────────────────────────────────────────────────────

pub fn main() {
  let tests = [
    #("taint: extracts names", taint_extracts_names()),
    #("ssrf: flags var arg", ssrf_flags_var()),
    #("ssrf: ignores literal", ssrf_ignores_literal()),
    #("ssrf: flags tainted", ssrf_flags_tainted()),
    #("ssrf: all http methods", ssrf_all_methods()),
    #("ssrf: ignores non-http", ssrf_ignores_non_http()),
    #("cmdi: flags system", cmdi_flags_system()),
    #("cmdi: flags Process.run", cmdi_flags_process_run()),
    #("cmdi: ignores literal", cmdi_ignores_literal()),
    #("pt: flags File.read", pt_flags_file_read()),
    #("pt: ignores literal", pt_ignores_literal()),
    #("pt: flags Dir.glob", pt_flags_dir_glob()),
    #("sqli: flags DB.query", sqli_flags_db_query()),
    #("sqli: ignores literal", sqli_ignores_literal()),
    #("integration: run_all combines", run_all_combines()),
    #("integration: run_all empty", run_all_empty()),
  ]

  let failures = list.filter(tests, fn(t) { !t.1 })
  let _pass = list.length(tests) - list.length(failures)

  io.println("")
  case list.length(failures) {
    0 -> {
      io.println(
        "✓ All " <> int.to_string(list.length(tests)) <> " tests passed",
      )
    }
    _ -> {
      io.println(
        "✗ "
        <> int.to_string(list.length(failures))
        <> " of "
        <> int.to_string(list.length(tests))
        <> " tests FAILED:",
      )
      list.each(failures, fn(f) { io.println("  - " <> f.0) })
    }
  }
  io.println("")
}
