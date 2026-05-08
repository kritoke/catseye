import catseye/node.{
  type Finding, type Node, ArgCall, ArgLiteral, ArgVar, Call, Finding,
}
import gleam/list
import gleam/string

// ── Evil regex patterns ───────────────────────────────────────────────
// These patterns indicate catastrophic backtracking (ReDoS) vulnerability.
// Nested quantifiers like (a+)+ or overlapping groups like ([a-zA-Z]+)*
// can cause exponential backtracking on crafted input.

/// Known dangerous regex patterns that indicate ReDoS risk
const evil_patterns = [
  // Nested quantifiers: (x+)+, (x*)+, (x+)*, (x*)*, (x?)+
  "+)+", "+)*", "*)+", "*)*", "?)", "?)+", "?)*",
  // Overlapping alternation with repetition
  "||)+", "||)*",
]

/// Check if a string literal looks like a regex with evil patterns
fn has_evil_pattern(s: String) -> Bool {
  list.any(evil_patterns, fn(p) { string.contains(s, p) })
}

/// Check if a node is a Regex.new / Regex.compile call
fn is_regex_call(name: String) -> Bool {
  string.contains(name, "Regex.new")
  || string.contains(name, "Regex.compile")
  || string.contains(name, "regex.compile")
  || string.contains(name, "re.compile")
  || string.contains(name, "regexp.compile")
}

/// Extract the regex pattern string from args
fn get_pattern_arg(node: Node) -> String {
  case node.args {
    [first, ..] ->
      case first.arg_type {
        ArgLiteral -> first.value
        ArgCall -> first.value
        ArgVar -> first.value
        _ -> ""
      }
    [] -> ""
  }
}

pub fn check(nodes: List(Node)) -> List(Finding) {
  nodes
  |> list.filter(fn(n) { n.node_type == Call && is_regex_call(n.name) })
  |> list.filter(fn(n) {
    let pattern = get_pattern_arg(n)
    has_evil_pattern(pattern)
  })
  |> list.map(fn(n) {
    let pattern = get_pattern_arg(n)
    Finding(
      rule: "ReDoS",
      severity: "Medium",
      file: n.file,
      line: n.line,
      message: "Potential ReDoS: "
        <> n.name
        <> " contains a regex with nested quantifiers or overlapping groups: "
        <> string.slice(pattern, 0, 60)
        <> ". This can cause catastrophic backtracking on crafted input. "
        <> "Simplify the regex or add input length limits.",
      flow: [],
    )
  })
}
