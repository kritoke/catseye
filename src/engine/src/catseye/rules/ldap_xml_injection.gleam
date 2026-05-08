import catseye/node.{type Finding, type Node, Call, Finding}
import catseye/rules/taint.{type TaintDB, build_finding_flow, is_suspect}
import gleam/list
import gleam/string

// ── LDAP / XML Injection detection ────────────────────────────────────
// Detects tainted data flowing into LDAP filter construction
// or XPath/XML query building without sanitization.

fn is_ldap_call(name: String) -> Bool {
  list.any(
    [
      "LDAP.search", "LDAP.query", "ldap.search", "ldap.query",
      "ldap_conn.search", "ldap_conn.bind", ":eldap.search", "eldap.search",
    ],
    fn(p) { string.contains(name, p) },
  )
}

fn is_xml_injection_call(name: String) -> Bool {
  list.any(
    [
      "XML.parse", "XML.XPath", "xpath", "XML.select", "Xml.parse", "Xml.xpath",
      "Nokogiri.HTML", "Nokogiri.XML", ":xmerl_scan.string", "xmerl_scan.string",
      "saxy.parse",
    ],
    fn(p) { string.contains(name, p) },
  )
}

pub fn check(
  nodes: List(Node),
  tainted: List(String),
  db: TaintDB,
) -> List(Finding) {
  // LDAP injection
  let ldap_findings =
    nodes
    |> list.filter(fn(n) { n.node_type == Call && is_ldap_call(n.name) })
    |> list.filter(fn(n) { is_suspect(n, tainted) })
    |> list.map(fn(n) {
      Finding(
        rule: "LDAPInjection",
        severity: "High",
        file: n.file,
        line: n.line,
        message: "Potential LDAP injection via "
          <> n.name
          <> ". User input may flow into an LDAP filter. "
          <> "Use parameterized LDAP queries and escape special characters (*, (, ), \\, NUL).",
        flow: build_finding_flow(db, n),
      )
    })

  // XML / XPath injection
  let xml_findings =
    nodes
    |> list.filter(fn(n) {
      n.node_type == Call && is_xml_injection_call(n.name)
    })
    |> list.filter(fn(n) { is_suspect(n, tainted) })
    |> list.map(fn(n) {
      Finding(
        rule: "XMLInjection",
        severity: "Medium",
        file: n.file,
        line: n.line,
        message: "Potential XML/XPath injection via "
          <> n.name
          <> ". User input may flow into XML parsing or XPath queries. "
          <> "This can enable XXE attacks or XPath injection. Use safe parsers and disable external entities.",
        flow: build_finding_flow(db, n),
      )
    })

  list.append(ldap_findings, xml_findings)
}
