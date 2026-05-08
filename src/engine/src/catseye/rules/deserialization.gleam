import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{type TaintDB, build_finding_flow, is_suspect}
import gleam/list
import gleam/string

// ── Insecure Deserialization detection ─────────────────────────────────
// Detects deserialization of untrusted data which can lead to
// remote code execution, denial of service, or authentication bypass.

fn is_deser_call(name: String) -> Bool {
  list.any(
    [
      // Crystal
      "JSON.parse", "JSON.mapping", "JSON::Serializable", "YAML.parse",
      "XML.parse", "Marshal.load", "Marshal.restore", "MessagePack.unpack",
      // Erlang/Elixir
      ":erlang.binary_to_term", "binary_to_term",
    ],
    fn(p) { string.contains(name, p) },
  )
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_deser_call(n.name) })
  |> list.filter(fn(n) { is_suspect(n, tainted) })
  |> list.map(fn(n) {
    Finding(
      rule: "InsecureDeserialization",
      severity: "High",
      file: n.file,
      line: n.line,
      message: "Potential insecure deserialization via "
        <> n.name
        <> ". Deserializing untrusted data can lead to RCE, DoS, or auth bypass. "
        <> "Validate and sanitize input before parsing, or use schema-based deserializers.",
      flow: build_finding_flow(db, n),
    )
  })
}
