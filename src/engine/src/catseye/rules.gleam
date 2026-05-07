//// Catseye Rules — facade module.
//// Computes taint once, runs all rules, combines findings.
//// Add new rules by creating a file in catseye/rules/ and
//// adding its check() call to run_all_rules below.

import catseye/node.{type Finding, type Node}
import catseye/rules/command_injection
import catseye/rules/path_traversal
import catseye/rules/sql_injection
import catseye/rules/ssrf
import catseye/rules/taint
import gleam/list

/// Run all security rules. Tainted vars computed once.
/// To add a rule: import it above, then append its check() here.
pub fn run_all_rules(nodes: List(Node)) -> List(Finding) {
  let tainted = taint.build_tainted_vars(nodes)
  let findings = ssrf.check(nodes, tainted)
  findings
  |> list.append(command_injection.check(nodes, tainted))
  |> list.append(path_traversal.check(nodes, tainted))
  |> list.append(sql_injection.check(nodes, tainted))
}
