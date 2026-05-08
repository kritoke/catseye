import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{type TaintDB, build_finding_flow, is_suspect}
import gleam/list
import gleam/string

// ── Open Redirect detection ────────────────────────────────────────────
// Detects unvalidated redirect/forward operations where user input
// controls the destination URL.

fn is_redirect_call(name: String) -> Bool {
  list.any(
    [
      // Crystal (Lucky/Kemal/Amber)
      "redirect", "redirect_to", "redirect_back", "response.redirect",
      "context.redirect", "HTTP::Response.redirect",
      // Gleam/Erlang
      "response.redirect", "cowboy_req.reply", "plug.conn.put_resp_header",
      // Generic
      "send_redirect", "location=",
    ],
    fn(p) { string.contains(name, p) || string.starts_with(name, p) },
  )
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_redirect_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    Finding(
      rule: "OpenRedirect",
      severity: "Medium",
      file: n.file,
      line: n.line,
      message: "Potential open redirect via "
        <> n.name
        <> ". User input may control the redirect destination. "
        <> "Validate URLs against an allowlist before redirecting.",
      flow: build_finding_flow(db, n),
    )
  })
}
