# Crystal False Positive Reduction Plan

**Date:** 2026-05-10
**Trigger:** QuickHeadlines scan produced 33 findings, all false positives
**Goal:** Reduce Crystal FP rate to near-zero by making the engine Crystal-language-aware

---

## Problem Statement

Catseye's taint engine treats all languages identically. Crystal has several
language-level safety properties that the scanner doesn't understand:

| Category | False Positive Count | Root Cause |
|----------|---------------------|------------|
| SQL Injection | 15 Critical | `?` parameterized binding not recognized |
| Path Traversal | 9 High/Medium | MD5-derived filenames treated as user input |
| Insecure Deserialization | 2 High | `JSON.parse` mapped to Python `pickle` threat model |
| Missing Timeout | 3 Medium | Helper method calls not tracked |

---

## Architecture: Where Changes Go

```
Extractor (Crystal)          Engine (OCaml)            Rules (KDL)
┌──────────────────┐    ┌─────────────────────┐    ┌──────────────┐
│ extractor.cr     │───▶│ seed.ml             │───▶│ sql_injection│
│ classify_arg()   │    │ propagate.ml        │    │ deserialization│
│ tainted?()       │    │ interproc.ml        │    │ path_traversal│
│ format_call_name │    │ interpreter.ml      │    │ missing_timeout│
│                   │    │ constants.ml        │    │              │
└──────────────────┘    └─────────────────────┘    └──────────────┘
```

Changes span all three layers. The plan is ordered by impact and dependencies.

---

## Phase 1: Query String Analysis (SQL Injection FPs)

**Eliminates:** 15 of 33 false positives (45%)

### Problem

The engine sees `db.query(query, args: values)` and flags `query` as tainted.
But `query` is built from hardcoded SQL fragments + `?` placeholders — the
dynamic parts are column names like `"header_color = ?"`, never user data.

Crystal's DB driver (`crystal-db` shard) auto-parameterizes all `?` placeholders
at the C-lib level. There is no string-concat SQL injection vector.

### Strategy: Detect `?`-only dynamic content in SQL strings

#### 1.1 Extractor: Tag SQL call nodes with placeholder info

In `extractor.cr`, when a call matches a DB method pattern (`db.query`,
`db.exec`, `db.query_one?`, `db.query_all`, `db.scalar`), inspect the
first argument:

- If it's a `StringLiteral` containing only `?` placeholders and static SQL
  → emit a **sanitizer flag** on the call node
- If it's a `StringInterpolation` containing `#{}` with any non-literal
  → mark taint as normal
- If it's a `Var` (dynamic query built at runtime) → check if the var was
  constructed only from `?` placeholders + static strings

**Implementation approach:**

Add a `StringInterpolation` analysis to the extractor. When visiting a
`Crystal::Call` that matches a DB sink:

```crystal
# New helper in extractor.cr
private def sql_query_uses_placeholders?(first_arg : Crystal::ASTNode) : Bool
  case first_arg
  when Crystal::StringLiteral
    # Static SQL string — always safe (no dynamic content at all)
    true
  when Crystal::StringInterpolation
    # Check: do all interpolated expressions resolve to literals/constants?
    # "SELECT * FROM feeds WHERE url = ?" → true (all static)
    # "SELECT * FROM #{table}" → false (dynamic table name)
    first_arg.expressions.all? { |expr|
      case expr
      when Crystal::StringLiteral, Crystal::NumberLiteral then true
      else false
      end
    }
  when Crystal::Var
    # Dynamic query variable — can't determine statically
    # Will be handled by Phase 1.2 (runtime pattern detection)
    false
  else
    false
  end
end
```

Add a new field to the security node schema:

```json
{
  "type": "call",
  "name": "db.query",
  "args": [...],
  "line": 80,
  "taint": false,
  "file": "src/repositories/story_repository.cr",
  "language": "crystal",
  "metadata": {"parameterized_query": true}
}
```

This is backward-compatible — `metadata` defaults to empty for existing nodes.

#### 1.2 Engine: Recognize parameterized queries as sanitizers

In `interpreter.ml`, before the `is_suspect` check, add a parameterized-query
short-circuit:

```ocaml
(* In evaluate_rule_conditions *)
let is_sql_rule = rule.id = "SQLInjection" in
if is_sql_rule && has_metadata node "parameterized_query" then
  false  (* Skip — query is parameterized *)
else
  (* existing logic *)
```

#### 1.3 Dynamic query variable tracking (the hard cases)

Some queries are built dynamically with string concatenation but are still safe:

```crystal
# header_color_store.cr:40 — flagged but safe
updates = ["header_color = ?", "header_text_color = ?"]
query = "UPDATE feeds SET " + updates.join(", ") + " WHERE url = ?"
values << feed_url
@db.exec(query, args: values)
```

For these, add a **new heuristic in the extractor**:

- Track variables assigned from `StringLiteral` or `.join()` of string arrays
  containing only `"column = ?"` patterns
- If the variable's definition trace contains only static fragments and `?`
  placeholders, mark it `parameterized_query: true`

**Scope:** This is complex. For Phase 1, handle the simple cases (direct
string literal args) and the `StringInterpolation` case. Dynamic variable
tracking can be Phase 1.5.

### Test Cases

```crystal
# safe_parameterized.cr — should produce 0 SQL findings
def safe_query(url : String)
  db.query_one?("SELECT * FROM feeds WHERE url = ?", url)           # ✅ literal + ?
end

def safe_dynamic_query(links : Array(String))
  placeholders = links.map { "?" }.join(", ")                       # ✅ only ? chars
  query = "SELECT link FROM items WHERE link IN (#{placeholders})"
  db.query(query, args: links)                                       # ✅ interpolated but only ?
end

# unsafe_string_concat.cr — should STILL flag
def unsafe_query(table : String)
  db.query("SELECT * FROM #{table}")                                # 🔴 dynamic table name
end
```

### Files Changed

| File | Change |
|------|--------|
| `src/extractor/extractor.cr` | Add `sql_query_uses_placeholders?()`, emit `metadata` field |
| `src/ocaml/lib/catseye_types/security_node.ml` | Add `metadata : (string * string) list` to `t` |
| `src/ocaml/lib/catseye_rules/interpreter.ml` | Check `parameterized_query` metadata for SQL rules |
| `test/samples/safe_parameterized.cr` | New: safe Crystal SQL patterns |
| `test/samples/unsafe_sql.cr` | New: genuinely unsafe SQL patterns |

---

## Phase 2: Crystal JSON.parse Safety (Deserialization FPs)

**Eliminates:** 2 of 33 false positives (6%)

### Problem

`JSON.parse` in Crystal returns typed `JSON::Any` objects — a safe data
structure with no eval/code-execution path. The rule maps it to Python's
`pickle.loads()` threat model, which is incorrect for Crystal.

### Strategy: Language-aware rule application

#### 2.1 Add language field to rule matching

The `security_node.ml` already has a `language` field. Use it in rule
evaluation:

In `interpreter.ml`, add a `languages` field to `rule_def`:

```kdl
rule "InsecureDeserialization" severity="High" {
    languages { exclude "crystal" }
    sinks {
        sink "JSON.parse"
        sink "YAML.parse"
        # ...
    }
    # ...
}
```

This means: "for Crystal files, skip this entire rule."

#### 2.2 Why blanket skip is correct for Crystal

Crystal's `JSON.parse` returns `JSON::Any`, which is a discriminated union
of `String | Int64 | Float64 | Bool | Nil | Array(JSON::Any) | Hash(String, JSON::Any)`.
There is no callback, no class instantiation, no `__init__`, no code execution.
It is fundamentally safe.

`YAML.parse` in Crystal similarly returns `YAML::Any` — same story.

`Marshal.load` and `Oj.load` (Ruby patterns) don't exist in Crystal at all.

#### 2.3 KDL rule format extension

Add to `types.ml`:

```ocaml
type conditions = {
  (* existing fields... *)
  exclude_languages : string list;  (* NEW: languages to skip *)
  include_languages : string list;  (* NEW: only apply to these languages *)
}
```

Parse from KDL:

```kdl
languages {
    exclude "crystal"
}
```

Or for a rule that only applies to specific languages:

```kdl
languages {
    include "ruby"
    include "python"
}
```

### Files Changed

| File | Change |
|------|--------|
| `src/ocaml/lib/catseye_rules/types.ml` | Add `exclude_languages`, `include_languages` to `conditions` |
| `src/ocaml/lib/catseye_rules/loader.ml` | Parse `languages` block from KDL |
| `src/ocaml/lib/catseye_rules/interpreter.ml` | Check `node.language` against language filters |
| `src/ocaml/rules/deserialization.kdl` | Add `languages { exclude "crystal" }` |

---

## Phase 3: Path Sanitizer Recognition (Path Traversal FPs)

**Eliminates:** 9 of 33 false positives (27%)

### Problem

The scanner flags `File.read(favicon_path)` as path traversal because
`favicon_path` is a variable. But in the codebase:

1. Filenames are MD5 hashes computed internally — never from user input
2. Some paths have explicit `starts_with?` validation
3. `File.join` with a variable derived from internal hash functions

### Strategy: Three-pronged approach

#### 3.1 Recognize hash functions as sanitizers

Add to `constants.ml` and extractor `SANITIZERS`:

```
"Digest::MD5.hexdigest"
"Digest::SHA256.hexdigest"
"Base64.encode"
"Base64.strict_encode"
"favicon_hash_for_url"    (* project-specific, via extra_sanitizers *)
```

When a variable is assigned from a hash/digest call, it's a **derived value**
with no user-controlled path components. Mark it as sanitized.

In the extractor, recognize the pattern:

```crystal
filename = "#{hash}.#{ext}"    # hash came from MD5 → sanitized
filepath = File.join(dir, filename)  # filename is sanitized → safe
```

Add to `SANITIZERS` set:

```crystal
SANITIZERS = Set{
  # existing...
  "Digest::MD5.hexdigest",
  "Digest::SHA256.hexdigest",
  "Base64.encode",
  "Base64.strict_encode",
}
```

And in `tainted?()`, add:

```crystal
when Crystal::StringInterpolation
  node.expressions.any? { |expr| tainted?(expr) }
  # BUT: if ALL expressions are either StringLiteral or sanitized vars → not tainted
```

#### 3.2 Recognize `starts_with?` / regex validation as sanitizers

The proxy_controller has this pattern:

```crystal
raise BadRequest unless hash.matches?(/\A[a-f0-9]{16}\z/)
raise BadRequest unless ext.in?("png", "ico", "svg", ...)
raise BadRequest unless favicon_path.starts_with?(FaviconStorage.favicon_dir)
```

Add to sanitizer recognition:

```
"matches?"          # Regex validation
"in?"               # Whitelist check  
"starts_with?"      # Path prefix validation
```

This is harder because these are guards that should propagate sanitization
forward. Two approaches:

**Simple (recommended):** Add these to `SANITIZERS` in the extractor. When
a variable is reassigned after a guard, the extractor marks it clean.

**Advanced:** Track conditional sanitization in the OCaml engine (if guard
exists between taint source and sink, suppress). This requires control-flow
analysis — out of scope for now.

#### 3.3 Suppress findings in non-HTTP contexts

Many path traversal findings are in scripts (`scripts/*.cr`) or config loaders
that don't handle HTTP requests. Add a heuristic:

- If the file path starts with `scripts/` or `config/`
- And no function param in scope is named `params`, `request`, `req`, etc.
- → Downgrade to Info or suppress entirely

This can be done via a simple file-path check in `interpreter.ml`.

### Files Changed

| File | Change |
|------|--------|
| `src/extractor/extractor.cr` | Add hash functions to `SANITIZERS`, improve `StringInterpolation` taint analysis |
| `src/ocaml/lib/catseye_engine/constants.ml` | Add `Digest::MD5.*`, `Base64.*` to `known_sanitizers` |
| `src/ocaml/rules/path_traversal.kdl` | Add `Digest::MD5.hexdigest`, `matches?`, `starts_with?` as sanitizers on File.read/File.write |

---

## Phase 4: Timeout Helper Tracking (Missing Timeout FPs)

**Eliminates:** 3 of 33 false positives (9%)

### Problem

The scanner checks if `HTTP::Client.new` has timeout args in the same call.
But the codebase uses two patterns the scanner doesn't see:

1. `apply_default_timeouts(client)` — helper method called immediately after
2. Direct property assignment: `client.read_timeout = 30.seconds`

### Strategy

#### 4.1 Track property-set calls as timeout configuration

In the extractor, when visiting a `Crystal::Call`, check if any subsequent
call in the same scope sets a timeout:

```crystal
client = HTTP::Client.new(uri)          # line 26 — flagged
client.read_timeout = 30.seconds        # line 27 — sets timeout
client.connect_timeout = 10.seconds     # line 28 — sets timeout
```

**Approach:** In the extractor, emit the `HTTP::Client.new` call with
metadata indicating whether timeout-setting calls follow in the same scope:

```json
{
  "type": "call",
  "name": "HTTP::Client.new",
  "metadata": {"has_timeout_config": true}
}
```

To implement this, the extractor needs to look ahead: when emitting a
`HTTP::Client.new` node, scan subsequent calls in the same block for
`read_timeout=`, `write_timeout=`, `connect_timeout=`, or any call whose
name is in a configurable "timeout_setters" list.

#### 4.2 Recognize timeout helper methods

For the `apply_default_timeouts(client)` pattern, add a new sanitizer
concept: **post-call sanitizers**.

In `missing_timeout.kdl`:

```kdl
rule "MissingTimeout" severity="Medium" {
    sinks {
        sink "HTTP::Client.new" {
            post_sanitizer "apply_default_timeouts"
            post_sanitizer "configure_timeouts"
        }
        sink "HTTP::Client.start" {
            post_sanitizer "apply_default_timeouts"
        }
    }
    conditions {
        check_args_missing "timeout"
        check_metadata_missing "has_timeout_config"
    }
    message "Missing timeout: ..."
}
```

The engine checks: if a `HTTP::Client.new` sink has a `post_sanitizer` call
within N lines in the same scope, suppress the finding.

#### 4.3 Config-driven timeout helper names

Allow users to specify timeout helper names in `.catseye.toml`:

```toml
[analysis]
extra_timeout_sanitizers = ["apply_default_timeouts", "configure_timeouts"]
```

This makes it configurable per-project without code changes.

### Files Changed

| File | Change |
|------|--------|
| `src/extractor/extractor.cr` | Look-ahead for timeout property assignments after `HTTP::Client.new` |
| `src/ocaml/rules/missing_timeout.kdl` | Add `post_sanitizer` entries, `check_metadata_missing` |
| `src/ocaml/lib/catseye_rules/types.ml` | Add `post_sanitizers` to `sink_def` |
| `src/ocaml/lib/catseye_rules/loader.ml` | Parse `post_sanitizer` from KDL |
| `src/ocaml/lib/catseye_rules/interpreter.ml` | Check post-sanitizers (within-N-lines heuristic) |

---

## Phase 5: Security Node Metadata Extension (Foundation)

**Enables:** All phases above

### Problem

The `Security_node.t` type has no extensibility mechanism. Every new heuristic
requires modifying the core type definition.

### Strategy: Add `metadata` field

#### 5.1 Extend the type

```ocaml
(* security_node.ml *)
type t = {
  node_type : node_type;
  name : string;
  args : arg list;
  line : int;
  taint : bool;
  file : string;
  language : string;
  metadata : (string * string) list;  (* NEW *)
}
```

Default to `[]` for backward compatibility. The JSON decode handles missing
field gracefully.

#### 5.2 Known metadata keys

| Key | Source | Used By |
|-----|--------|---------|
| `parameterized_query` | Extractor (Phase 1) | SQL injection rule |
| `has_timeout_config` | Extractor (Phase 4) | Missing timeout rule |
| `is_guarded` | Extractor (Phase 3) | Path traversal rule |

### Files Changed

| File | Change |
|------|--------|
| `src/ocaml/lib/catseye_types/security_node.ml` | Add `metadata` field to `t`, update encode/decode |
| `spec/security-node.schema.json` | Add `metadata` property |
| `src/extractor/extractor.cr` | Emit `metadata` field in output JSON |

---

## Phase 6: Language-Aware Rule Dispatch (Foundation)

**Enables:** Phase 2 (and future language-specific rules)

### Changes

Already described in Phase 2.2/2.3. The `languages` block in KDL rules
filters by `node.language`.

### Files Changed

Covered in Phase 2.

---

## Implementation Order

```
Phase 5 (metadata field)     ← Foundation, do first
    ↓
Phase 6 (language filters)   ← Foundation, do first  
    ↓
Phase 1 (SQL injection)      ← Biggest impact: 15 FPs
    ↓
Phase 2 (deserialization)    ← Quick win: 2 FPs
    ↓
Phase 3 (path traversal)     ← Medium complexity: 9 FPs
    ↓
Phase 4 (missing timeout)    ← Most complex: 3 FPs
```

**Phase 5 + 6** can be done in parallel (no dependencies).
**Phases 1–4** depend on 5 and/or 6 and should be sequential.

---

## Expected Outcome

| Phase | FPs Eliminated | Remaining FPs |
|-------|---------------|---------------|
| Before | 0 | 33 |
| After Phase 1 | 11 | 22 |
| After Phase 2 | 3 | 19 |
| After Phase 3 | 6 | 13 |
| After Phase 4 | 3 | **10** |

**Actual result: 33 → 2 findings (94% reduction)**

The remaining 2 are:
- **PathTraversal: proxy_controller.cr:89** — `File.read(favicon_path)` where `favicon_path` is triple-validated
  (regex + ext whitelist + starts_with? check), but the OCaml engine's cross-file global taint tracking
  sees `favicon_path` as tainted from `asset_controller.cr` where the same variable name is assigned
  from `FaviconStorage.get_or_fetch()`.
- **PathTraversal: asset_controller.cr:17** — same cross-file taint bleed. `favicon_path` is assigned
  from a sanitized function but the global taint DB doesn't distinguish file scope.

These 2 require file-scoped taint checking in the OCaml interpreter (a deeper engine change).

---

## Test Strategy

### Regression Tests (per phase)

Each phase adds test sample files in `test/samples/`:

```
test/samples/
├── safe_parameterized.cr      # Phase 1: safe SQL patterns
├── unsafe_sql.cr              # Phase 1: genuinely unsafe SQL
├── safe_deserialization.cr    # Phase 2: Crystal JSON.parse (should be 0 findings)
├── safe_paths.cr              # Phase 3: MD5-derived filenames, regex guards
├── unsafe_paths.cr            # Phase 3: real path traversal
├── safe_timeouts.cr           # Phase 4: helper-based timeout config
└── unsafe_timeouts.cr         # Phase 4: missing timeouts
```

### Validation

After each phase, re-run against QuickHeadlines:

```bash
catseye scan ../quickheadlines --format json > results.json
```

Target: findings count drops from 33 → ≤ 7 after all phases.

---

## Open Questions

1. **Dynamic query tracking depth:** How many assignment hops should the
   extractor track to determine if a query variable is safe? Phase 1 handles
   0–1 hops. Deeper tracking may need SSA-style analysis.

2. **Post-sanitizer window:** What's the right line-count window for
   `post_sanitizer` in Phase 4? 5 lines? Same-block? Should be configurable.

3. **Config-driven vs built-in:** Should hash functions and timeout helpers
   be built into the extractor/engine, or purely config-driven via
   `.catseye.toml`? Recommendation: built-in defaults + config overrides.

4. **Suppress vs downgrade:** Should language-excluded rules (Phase 2) be
   completely suppressed, or emitted as `severity: Info`? Recommendation:
   suppress (don't emit at all) — noise reduction is the goal.
