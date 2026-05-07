import catseye/node.{type Finding, type Node}
import catseye/rules/command_injection
import catseye/rules/path_traversal
import catseye/rules/sql_injection
import catseye/rules/ssrf
import catseye/rules/taint
import gleam/list

pub fn run_all_rules(nodes: List(Node)) -> List(Finding) {
  let db = taint.build_taint_db(nodes)
  let tainted = taint.tainted_vars_list(db)
  ssrf.check(nodes, tainted, db)
  |> list.append(command_injection.check(nodes, tainted, db))
  |> list.append(path_traversal.check(nodes, tainted, db))
  |> list.append(sql_injection.check(nodes, tainted, db))
}
