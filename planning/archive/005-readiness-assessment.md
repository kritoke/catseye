# Catseye Readiness Assessment

## Can you run it against a real codebase? **Yes, with caveats.**

### What works now
- ✅ Scans any directory of `.cr` files recursively
- ✅ Detects SSRF, command injection (real findings)
- ✅ Taint propagation from params/gets/request → variable → sink
- ✅ Correctly ignores hardcoded literal URLs
- ✅ Colored CLI output, CI-friendly exit codes
- ✅ Modular rule system — easy to add new rules

### Known limitations for real-world use

1. **False positives on string interpolation**
   - `HTTP::Client.get("https://api.example.com/users/#{id}")` is flagged
   - The extractor sees `#{id}` as a call node, treats it as variable
   - These are technically worth reviewing but noisy in practice

2. **No inter-procedural taint tracking**
   - Taint only flows within a single method body
   - If `fetch_url(url)` is called from `handle_request`, the taint
     from `params` won't cross the function boundary

3. **No Crystal stdlib awareness**
   - Doesn't know which Crystal methods are "safe" sanitizers
   - `URI.encode(url)` still flagged even though it normalizes input

4. **Path traversal / SQL injection rules need real-world testing**
   - Patterns like `File.read`, `DB.query` are guessed, not from a
     specific Crystal framework. May miss framework-specific APIs.

5. **No SARIF/JSON output mode from CLI**
   - Currently only prints human-readable terminal output
   - CI integration would need `--format json` or `--format sarif`

6. **Extractor requires Crystal compiler**
   - The `Crystal::Parser` dependency means you need Crystal installed
   - Can't analyze .cr files without the full Crystal toolchain

### What to do next for production readiness

Priority order:
1. Add `--format json` output to Nim CLI (enables CI tooling)
2. Reduce interpolation false positives (track literal + interpolation mix)
3. Test against a real Crystal web framework (Lucky, Amber, Kemal)
4. Add sanitizer recognition (skip flagged nodes after known sanitizers)
5. Inter-procedural taint tracking (cross function boundaries)
