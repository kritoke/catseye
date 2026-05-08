import catseye/node.{type Finding, type Node, Call, Finding}
import gleam/list
import gleam/string

// ── Hardcoded secret patterns ─────────────────────────────────────────
// Detects API keys, passwords, tokens, and other credentials
// embedded directly in source code.

/// Variable names that suggest they hold secrets
const secret_var_names = [
  "password", "passwd", "pass", "secret", "api_key", "apikey", "access_token",
  "accesstoken", "auth_token", "authtoken", "private_key", "privatekey",
  "secret_key", "secretkey", "db_password", "dbpasswd", "database_url",
  "aws_secret", "aws_access_key",
]

fn is_secret_assign_name(name: String) -> Bool {
  let lower = string.lowercase(name)
  list.any(secret_var_names, fn(p) { string.contains(lower, p) })
}

pub fn check(nodes: List(Node)) -> List(Finding) {
  // Check calls where name suggests a secret AND the call is tainted
  // (meaning it receives data that could be user-controlled)
  nodes
  |> list.filter(fn(n) {
    n.node_type == Call && is_secret_assign_name(n.name) && n.taint
  })
  |> list.map(fn(n) {
    Finding(
      rule: "HardcodedSecret",
      severity: "High",
      file: n.file,
      line: n.line,
      message: "Potential hardcoded secret: "
        <> n.name
        <> " appears to contain a credential or API key. "
        <> "Use environment variables or a secrets manager instead.",
      flow: [],
    )
  })
}
