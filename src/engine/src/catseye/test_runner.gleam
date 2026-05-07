//// Catseye Engine test runner (no eunit dependency)
//// Run: cd src/engine && gleam run -m catseye/test_runner

import gleam/io
import gleam/int
import gleam/list
import catseye/node.{
  type Node, type Arg,
  Node, Arg,
  Assign, Call,
  ArgVar, ArgLiteral,
}
import catseye/ssrf

// ── Helpers ────────────────────────────────────────────────────────────

fn node_(type_: node.NodeType, name: String, args: List(Arg), taint: Bool) -> Node {
  Node(node_type: type_, name: name, args: args, line: 1, taint: taint, file: "test.cr")
}

fn arg_(type_: node.ArgType, value: String) -> Arg {
  Arg(arg_type: type_, value: value)
}

// ── Assertion helper ───────────────────────────────────────────────────

fn assert_eq(label: String, got: a, want: a) -> Bool {
  case got == want {
    True -> True
    False -> {
      io.println("  FAIL: " <> label)
      False
    }
  }
}

// ── Tests ──────────────────────────────────────────────────────────────

fn ssrf_flags_var() -> Bool {
  let nodes = [node_(Call, "HTTP::Client.get", [arg_(ArgVar, "url")], False)]
  let findings = ssrf.check_ssrf(nodes, [])
  assert_eq("ssrf flags var", list.length(findings), 1)
}

fn ssrf_ignores_literal() -> Bool {
  let nodes = [
    node_(Call, "HTTP::Client.get", [arg_(ArgLiteral, "https://example.com")], False),
  ]
  let findings = ssrf.check_ssrf(nodes, [])
  assert_eq("ssrf ignores literal", list.length(findings), 0)
}

fn ssrf_flags_tainted() -> Bool {
  let nodes = [
    node_(Assign, "target", [arg_(ArgVar, "params")], True),
    node_(Call, "HTTP::Client.get", [arg_(ArgVar, "target")], False),
  ]
  let tainted = ssrf.build_tainted_vars(nodes)
  let findings = ssrf.check_ssrf(nodes, tainted)
  assert_eq("ssrf flags tainted", list.length(findings), 1)
}

fn ssrf_all_http_methods() -> Bool {
  let nodes = list.map(
    ["HTTP::Client.get", "HTTP::Client.post", "HTTP::Client.put", "HTTP::Client.delete"],
    fn(m) { node_(Call, m, [arg_(ArgVar, "url")], False) },
  )
  let findings = ssrf.check_ssrf(nodes, [])
  assert_eq("ssrf all methods", list.length(findings), 4)
}

fn ssrf_ignores_non_http() -> Bool {
  let nodes = [
    node_(Call, "puts", [arg_(ArgVar, "data")], False),
    node_(Call, "JSON.parse", [arg_(ArgVar, "input")], False),
  ]
  let findings = ssrf.check_ssrf(nodes, [])
  assert_eq("ssrf ignores non-http", list.length(findings), 0)
}

fn cmdi_flags_system() -> Bool {
  let nodes = [node_(Call, "system", [arg_(ArgVar, "cmd")], False)]
  let findings = ssrf.check_command_injection(nodes, [])
  assert_eq("cmdi flags system", list.length(findings), 1)
}

fn cmdi_ignores_literal() -> Bool {
  let nodes = [node_(Call, "system", [arg_(ArgLiteral, "echo hello")], False)]
  let findings = ssrf.check_command_injection(nodes, [])
  assert_eq("cmdi ignores literal", list.length(findings), 0)
}

fn run_all_combines() -> Bool {
  let nodes = [
    node_(Call, "HTTP::Client.get", [arg_(ArgVar, "url")], False),
    node_(Call, "system", [arg_(ArgVar, "cmd")], False),
  ]
  let findings = ssrf.run_all_rules(nodes)
  assert_eq("run_all combines", list.length(findings), 2)
}

fn run_all_empty() -> Bool {
  let findings = ssrf.run_all_rules([])
  assert_eq("run_all empty", list.length(findings), 0)
}

fn tainted_vars_tracking() -> Bool {
  let nodes = [
    node_(Assign, "x", [arg_(ArgVar, "params")], True),
    node_(Assign, "y", [arg_(ArgLiteral, "safe")], False),
    node_(Assign, "z", [arg_(ArgVar, "gets")], True),
  ]
  let tainted = ssrf.build_tainted_vars(nodes)
  assert_eq("tainted count", list.length(tainted), 2)
  && assert_eq("tainted has x", list.contains(tainted, "x"), True)
  && assert_eq("tainted not y", list.contains(tainted, "y"), False)
}

// ── Runner ─────────────────────────────────────────────────────────────

pub fn main() {
  let tests = [
    #("SSRF flags var arg", ssrf_flags_var()),
    #("SSRF ignores literal", ssrf_ignores_literal()),
    #("SSRF flags tainted", ssrf_flags_tainted()),
    #("SSRF all http methods", ssrf_all_http_methods()),
    #("SSRF ignores non-http", ssrf_ignores_non_http()),
    #("CMDI flags system", cmdi_flags_system()),
    #("CMDI ignores literal", cmdi_ignores_literal()),
    #("run_all combines", run_all_combines()),
    #("run_all empty", run_all_empty()),
    #("tainted vars tracking", tainted_vars_tracking()),
  ]

  let failures = list.filter(tests, fn(t) { !t.1 })
  let _pass = list.length(tests) - list.length(failures)

  io.println("")
  case list.length(failures) {
    0 -> {
      io.println(
        "✓ All " <> int.to_string(list.length(tests)) <> " tests passed"
      )
    }
    _ -> {
      io.println(
        "✗ " <> int.to_string(list.length(failures)) <> " of "
          <> int.to_string(list.length(tests)) <> " tests FAILED:"
      )
      list.each(failures, fn(f) { io.println("  - " <> f.0) })
    }
  }
  io.println("")
}
