import catseye/node.{type Finding, type Node}
import catseye/rules/command_injection
import catseye/rules/deserialization
import catseye/rules/hardcoded_secrets
import catseye/rules/ldap_xml_injection
import catseye/rules/open_redirect
import catseye/rules/path_traversal
import catseye/rules/redos
import catseye/rules/sql_injection
import catseye/rules/ssrf
import catseye/rules/taint
import catseye/rules/weak_crypto
import gleam/list

pub fn run_all_rules(nodes: List(Node)) -> List(Finding) {
  let db = taint.build_taint_db(nodes)
  let tainted = taint.tainted_vars_list(db)
  ssrf.check(nodes, tainted, db)
  |> list.append(command_injection.check(nodes, tainted, db))
  |> list.append(path_traversal.check(nodes, tainted, db))
  |> list.append(sql_injection.check(nodes, tainted, db))
  |> list.append(redos.check(nodes))
  |> list.append(hardcoded_secrets.check(nodes))
  |> list.append(open_redirect.check(nodes, tainted, db))
  |> list.append(deserialization.check(nodes, tainted, db))
  |> list.append(ldap_xml_injection.check(nodes, tainted, db))
  |> list.append(weak_crypto.check(nodes))
}

pub fn run_all_rules_with_config(
  nodes: List(Node),
  extra_sources: List(String),
  extra_sanitizers: List(String),
) -> List(Finding) {
  let db =
    taint.build_taint_db_with_config(nodes, extra_sources, extra_sanitizers)
  let tainted = taint.tainted_vars_list(db)
  ssrf.check(nodes, tainted, db)
  |> list.append(command_injection.check(nodes, tainted, db))
  |> list.append(path_traversal.check(nodes, tainted, db))
  |> list.append(sql_injection.check(nodes, tainted, db))
  |> list.append(redos.check(nodes))
  |> list.append(hardcoded_secrets.check(nodes))
  |> list.append(open_redirect.check(nodes, tainted, db))
  |> list.append(deserialization.check(nodes, tainted, db))
  |> list.append(ldap_xml_injection.check(nodes, tainted, db))
  |> list.append(weak_crypto.check(nodes))
}
