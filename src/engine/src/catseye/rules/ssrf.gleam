import catseye/node.{
  type Finding, type Node, ArgCall, ArgLiteral, ArgVar, Call, Finding,
}
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

/// Check if an HTTP call has tls_verify: false or verify_mode: NONE
fn has_insecure_tls(node: Node) -> Bool {
  list.any(node.args, fn(a) {
    case a.arg_type {
      ArgVar ->
        string.contains(a.value, "tls_verify")
        || string.contains(a.value, "verify_mode")
      ArgCall ->
        string.contains(a.value, "OpenSSL::SSL::VerifyMode::NONE")
        || string.contains(a.value, "tls_verify")
        || string.contains(a.value, "verify_mode")
      ArgLiteral ->
        string.contains(a.value, "tls_verify")
        || string.contains(a.value, "verify_mode")
      _ -> False
    }
  })
}

/// Check if an HTTP::Client.new/start lacks timeout settings
/// Pattern: HTTP::Client.new or HTTP::Client.start without connect_timeout/read_timeout args
fn has_missing_timeout(node: Node) -> Bool {
  let name = node.name
  case
    string.contains(name, "HTTP::Client.new")
    || string.contains(name, "HTTP::Client.start")
    || string.contains(name, "HTTP::Client.new")
  {
    False -> False
    True ->
      // If there are args but none mention timeout, flag it
      case node.args {
        [] -> False
        args -> !list.any(args, fn(a) { string.contains(a.value, "timeout") })
      }
  }
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  // A1: SSRF via tainted URL
  let ssrf_findings =
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

  // A2: Insecure TLS (tls_verify: false)
  let tls_findings =
    nodes
    |> list.filter(fn(n) {
      n.node_type == Call && is_http_call(n.name) && has_insecure_tls(n)
    })
    |> list.map(fn(n) {
      Finding(
        rule: "InsecureTLS",
        severity: "High",
        file: n.file,
        line: n.line,
        message: "Insecure TLS: "
          <> n.name
          <> " disables certificate verification (tls_verify: false / verify_mode: NONE). "
          <> "This allows MITM attacks. Remove tls_verify: false or set verify_mode to PEER.",
        flow: [],
      )
    })

  // A3: Missing HTTP timeout (Slowloris risk)
  let timeout_findings =
    nodes
    |> list.filter(fn(n) { n.node_type == Call && has_missing_timeout(n) })
    |> list.map(fn(n) {
      Finding(
        rule: "MissingTimeout",
        severity: "Medium",
        file: n.file,
        line: n.line,
        message: "Missing timeout: "
          <> n.name
          <> " does not set connect_timeout or read_timeout. "
          <> "This enables Slowloris DoS attacks. Add explicit timeout values.",
        flow: [],
      )
    })

  list.flatten([ssrf_findings, tls_findings, timeout_findings])
}
