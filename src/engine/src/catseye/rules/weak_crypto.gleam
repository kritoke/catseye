import catseye/node.{type Finding, type Node, Call, Finding}
import gleam/list
import gleam/string

// ── Weak Cryptography detection ───────────────────────────────────────
// Detects use of weak hashing algorithms (MD5, SHA1) for passwords,
// and insecure random number generation.

/// Check for weak hash call names (MD5, SHA1 explicitly)
fn uses_weak_algorithm(name: String) -> Bool {
  string.contains(name, "MD5")
  || string.contains(name, "SHA1")
  || string.contains(name, "md5")
  || string.contains(name, "sha1")
}

/// Insecure random number generators (non-cryptographic)
fn is_insecure_random(name: String) -> Bool {
  list.any(["rand", "Math.random", "Random.rand"], fn(p) {
    string.contains(name, p) && !string.contains(name, "Secure")
  })
}

pub fn check(nodes: List(Node)) -> List(Finding) {
  // D1: Weak hashing algorithms
  let hash_findings =
    nodes
    |> list.filter(fn(n) { n.node_type == Call && uses_weak_algorithm(n.name) })
    |> list.map(fn(n) {
      Finding(
        rule: "WeakCryptography",
        severity: "Medium",
        file: n.file,
        line: n.line,
        message: "Weak cryptography: "
          <> n.name
          <> " uses a weak hashing algorithm (MD5/SHA1). "
          <> "Use SHA-256 or stronger for security-sensitive operations. "
          <> "For passwords, use bcrypt, scrypt, or argon2.",
        flow: [],
      )
    })

  // D2: Insecure random (non-cryptographic RNG for security contexts)
  let random_findings =
    nodes
    |> list.filter(fn(n) { n.node_type == Call && is_insecure_random(n.name) })
    |> list.map(fn(n) {
      Finding(
        rule: "InsecureRandom",
        severity: "Low",
        file: n.file,
        line: n.line,
        message: "Insecure random: "
          <> n.name
          <> " may use a non-cryptographic PRNG. "
          <> "For security tokens, session IDs, or passwords, use SecureRandom or crypto:strong_rand_bytes.",
        flow: [],
      )
    })

  list.append(hash_findings, random_findings)
}
