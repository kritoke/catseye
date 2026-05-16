# Autofix / Suggested Fixes

**Change:** `autofix-suggestions`  
**Priority:** P1  
**Size:** M (2-3 days)

## Problem

When Catseye flags a vulnerability (e.g., SSRF via `HTTP::Client.get(url)`), it tells the developer *what's wrong* but not *how to fix it*. Developers must manually look up the correct sanitizer or pattern. This slows down remediation and increases the chance of incomplete fixes.

## Proposal

Add `fix` templates to KDL rule sink definitions. When a finding matches, the fix template is instantiated with the tainted variable names and returned as the `suggestion` field on `Finding.t` (which already exists). Terminal output renders the suggestion inline. SARIF output includes it as a fix suggestion.

## KDL Syntax

```kdl
sink "HTTP::Client.get" arg=0 {
    sanitizer "URI.parse"
    fix "HTTP::Client.get(URI.parse({arg0}))"
}
```

- `fix` is a quoted string with `{arg0}`, `{arg1}`, etc. placeholders for the tainted arguments
- `{sink}` placeholder for the original sink call
- If no `fix` is specified, `suggestion` is `None` (backward compatible)

## Examples

| Rule | Sink | Fix Template | Suggestion |
|------|------|-------------|------------|
| SSRF | `HTTP::Client.get(url)` | `HTTP::Client.get(URI.parse({arg0}))` | Wrap in `URI.parse` |
| PathTraversal | `File.read(path)` | `File.read(validate_path({arg0}))` | Validate path first |
| SQLInjection | `db.query(sql)` | `db.query(sanitize_sql({arg0}))` | Parameterize query |
| CommandInjection | `system(cmd)` | Use `Process.run` with array args | Use safe API |

## Scope

- KDL rule parsing of `fix` field
- Template substitution using existing `substitute_template`-style logic
- Terminal output: show `  💡 Suggestion: <fix>` after each finding
- JSON output: `suggestion` field already serialized
- SARIF output: map to `fix` object with `edits`
- Update 5 core rules (SSRF, PathTraversal, SQLInjection, CommandInjection, OpenRedirect)

## Out of Scope

- Automatic file patching (just suggestions, no writes)
- AI-generated fixes
- IDE integration (future work)
