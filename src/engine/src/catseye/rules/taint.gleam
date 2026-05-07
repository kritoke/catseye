//// Shared taint analysis infrastructure used by all rules.
//// Computed once per scan, passed to each rule.

import catseye/node.{
  type Arg, type Node, ArgCall, ArgVar, Assign, all_args_literal, has_var_args,
}
import gleam/list
import gleam/string

/// Collect variable names assigned from tainted sources.
pub fn build_tainted_vars(nodes: List(Node)) -> List(String) {
  nodes
  |> list.filter(fn(node) { node.node_type == Assign && node.taint })
  |> list.map(fn(node) { node.name })
}

/// Check if an arg references a tainted variable or string interpolation
pub fn arg_is_tainted(tainted: List(String), arg: Arg) -> Bool {
  case arg.arg_type {
    ArgVar -> list.contains(tainted, arg.value)
    ArgCall -> string.contains(arg.value, "<interpolation>")
    _ -> False
  }
}

/// Check if any arg on a node references a tainted variable
pub fn args_contain_tainted(tainted: List(String), node: Node) -> Bool {
  list.any(node.args, fn(a) { arg_is_tainted(tainted, a) })
}

/// A node is suspect if directly tainted, has variable args,
/// or references tainted variables. Excludes all-literal args.
pub fn is_suspect(node: Node, tainted: List(String)) -> Bool {
  { node.taint || has_var_args(node) || args_contain_tainted(tainted, node) }
  && !all_args_literal(node)
}

/// Extract variable argument names for messages
pub fn var_names_from_args(args: List(Arg)) -> String {
  args
  |> list.filter(fn(a) { a.arg_type == ArgVar })
  |> list.map(fn(a) { a.value })
  |> string.join(", ")
}
