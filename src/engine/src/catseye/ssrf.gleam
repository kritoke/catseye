//// Catseye Security Rules
////
//// Rule definitions for vulnerability detection. Each rule filters nodes
//// by call pattern, then checks for tainted/variable arguments.
//// Shared infrastructure is extracted to avoid duplication.

import gleam/list
import gleam/string
import catseye/node.{
  type Node, type Finding, type Arg,
  Assign, Call,
  ArgVar, ArgCall,
  has_var_args, all_args_literal,
  Finding,
}

// ── Taint tracking (shared) ────────────────────────────────────────────

/// Collect variable names assigned from tainted sources.
/// Computed once and passed to all rules.
pub fn build_tainted_vars(nodes: List(Node)) -> List(String) {
  nodes
  |> list.filter(fn(node) { node.node_type == Assign && node.taint })
  |> list.map(fn(node) { node.name })
}

/// Check if an arg references a tainted variable or string interpolation
fn arg_is_tainted(tainted: List(String), arg: Arg) -> Bool {
  case arg.arg_type {
    ArgVar -> list.contains(tainted, arg.value)
    ArgCall -> string.contains(arg.value, "<interpolation>")
    _ -> False
  }
}

/// Check if any arg on a node references a tainted variable
fn args_contain_tainted(tainted: List(String), node: Node) -> Bool {
  list.any(node.args, fn(a) { arg_is_tainted(tainted, a) })
}

// ── Shared rule predicate ──────────────────────────────────────────────

/// A node is suspect if it's directly tainted, has variable args,
/// or references tainted variables. Excludes all-literal args.
fn is_suspect(node: Node, tainted: List(String)) -> Bool {
  {
    node.taint || has_var_args(node) || args_contain_tainted(tainted, node)
  }
  && !all_args_literal(node)
}

// ── Call pattern matching ──────────────────────────────────────────────

fn is_http_call(name: String) -> Bool {
  list.any(
    [
      "HTTP::Client.get", "HTTP::Client.post", "HTTP::Client.put",
      "HTTP::Client.patch", "HTTP::Client.delete", "HTTP::Client.head",
      "HTTP::Client.options", "HTTP::Client.exec",
    ],
    fn(p) { string.starts_with(name, p) },
  )
}

fn is_shell_call(name: String) -> Bool {
  list.any(
    ["system", "exec", "Process.run", "``"],
    fn(p) { string.contains(name, p) },
  )
}

// ── Var name extraction (shared) ───────────────────────────────────────

fn var_names_from_args(args: List(Arg)) -> String {
  args
  |> list.filter(fn(a) { a.arg_type == ArgVar })
  |> list.map(fn(a) { a.value })
  |> string.join(", ")
}

// ── SSRF Rule ──────────────────────────────────────────────────────────

pub fn check_ssrf(nodes: List(Node), tainted: List(String)) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_http_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    Finding(
      rule: "SSRF",
      severity: "High",
      file: n.file,
      line: n.line,
      message: "Potential SSRF: " <> n.name
        <> " called with variable argument(s): "
        <> var_names_from_args(n.args)
        <> ". The URL may be user-controlled. Ensure URL validation and allowlisting is applied.",
    )
  })
}

// ── Command Injection Rule ─────────────────────────────────────────────

pub fn check_command_injection(nodes: List(Node), tainted: List(String)) -> List(Finding) {
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

// ── All Rules ──────────────────────────────────────────────────────────

/// Run all security rules. Tainted vars are computed once.
pub fn run_all_rules(nodes: List(Node)) -> List(Finding) {
  let tainted = build_tainted_vars(nodes)
  list.append(
    check_ssrf(nodes, tainted),
    check_command_injection(nodes, tainted),
  )
}
