import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{
  type TaintDB, build_finding_flow, is_suspect, var_names_from_args,
}
import gleam/list
import gleam/string

fn is_http_call(name: String) -> Bool {
  list.any(
    [
      "HTTP::Client.get", "HTTP::Client.post", "HTTP::Client.put",
      "HTTP::Client.patch", "HTTP::Client.delete", "HTTP::Client.head",
      "HTTP::Client.options", "HTTP::Client.exec", "hackney.get", "hackney.post",
      "hackney.put", "hackney.delete", "hackney.request", "httpc.request",
      "req.get", "req.post", "req.put", "req.delete", "req.request",
    ],
    fn(p) { string.starts_with(name, p) },
  )
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_http_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    let vars = var_names_from_args(n.args)
    Finding(
      rule: "SSRF",
      severity: "High",
      file: n.file,
      line: n.line,
      message: "Potential SSRF: "
        <> n.name
        <> " called with variable argument(s): "
        <> vars
        <> ". The URL may be user-controlled. Ensure URL validation and allowlisting is applied.",
      flow: build_finding_flow(db, n),
    )
  })
}
