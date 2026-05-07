//// SSRF detection rule.
//// Flags HTTP client calls with variable/tainted arguments.

import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{is_suspect, var_names_from_args}
import gleam/list
import gleam/string

fn is_http_call(name: String) -> Bool {
  list.any(
    [
      // Crystal
      "HTTP::Client.get", "HTTP::Client.post", "HTTP::Client.put",
      "HTTP::Client.patch", "HTTP::Client.delete", "HTTP::Client.head",
      "HTTP::Client.options", "HTTP::Client.exec",
      // Gleam/Erlang (hackney, req, httpc)
      "hackney.get", "hackney.post", "hackney.put", "hackney.delete",
      "hackney.request", "httpc.request", "req.get", "req.post", "req.put",
      "req.delete", "req.request",
    ],
    fn(p) { string.starts_with(name, p) },
  )
}

pub fn check(nodes: List(Node), tainted: List(String)) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_http_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    Finding(
      rule: "SSRF",
      severity: "High",
      file: n.file,
      line: n.line,
      message: "Potential SSRF: "
        <> n.name
        <> " called with variable argument(s): "
        <> var_names_from_args(n.args)
        <> ". The URL may be user-controlled. Ensure URL validation and allowlisting is applied.",
    )
  })
}
