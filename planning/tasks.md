# Catseye — Active Tasks

## In Progress

(None — ready for next task)

## Up Next

### Task: Enhanced sink & pattern detection (Priority Feature)

#### A. SSRF & Network Safety (highest priority for RSS aggregator use case)
- **Insecure default detection:** Flag `tls_verify: false` or `OpenSSL::SSL::VerifyMode::NONE`
- **Timeout check:** Flag any `HTTP::Client` instantiation missing `connect_timeout` or `read_timeout` (Slowloris prevention)
- **Existing:** HTTP::Client.get/post with non-hardcoded first arg (already implemented)

#### B. Command & SQL Injection (expanded sinks)
- **Crystal sinks:** `Process.run(command, ...)` especially with `shell: true`
- **SQL interpolation:** `DB#exec`/`DB#query`/`DB#scalar` with `#{variable}` interpolation vs `?` placeholders
- **Gleam/Erlang sinks:** `erlexec.Shell` (unsafe) vs `erlexec.Execve` (safe); direct `:os.cmd` calls
- **Existing:** `system()`, `os.command()` already detected

#### C. File System & Path Traversal (expanded patterns)
- **Pattern:** `File.join(base_dir, user_input)` — check if `user_input` is sanitized for `..` sequences
- **Existing:** `File.read`/`File.write`/`File.delete` with variable paths (already implemented)

#### D. Regular Expression Denial of Service (ReDoS) — NEW RULE
- **Check:** Scan all `Regex.new` calls for evil regex patterns:
  - Nested quantifiers: `(a+)+`
  - Overlapping groups with repetition: `([a-zA-Z]+)*`
- **Threat:** Malicious RSS feed with crafted string hangs Crystal at 100% CPU
- **Files:** New `catseye/rules/redos.gleam`, update Crystal extractor to emit Regex.new nodes

#### E. Environment variable injection — NEW PATTERN
- **Check:** Tainted data flowing into `ENV[]=` or `process environment` setters
- **Threat:** Attacker modifies PATH, LD_PRELOAD, etc.

### Task: `justfile` hardening
**Goal:** Make `just test` run the full E2E pipeline (build + extract + engine + assert findings)
**Approach:** Add assertion steps to verify expected finding counts

---

## Future / Planned

### Task: Software Composition Analysis (SCA) module
**Status:** Planned
**Language:** Nim (in CLI)
**Goal:** Scan dependency manifests for known vulnerabilities via OSV.dev API

**Spec:**
1. Detect `shard.yml` and `gleam.toml` in the project root
2. Parse the dependency list and pinned versions from each
3. Use Nim's `httpclient` to query the [OSV.dev API](https://osv.dev/docs/#api-) for known vulnerabilities in those specific versions
4. If a `high` or `critical` vulnerability is found, print a warning with a 🐈‍⬛ (Stray Cat) icon and the suggested upgrade version

**OSV API example:**
```
POST https://api.osv.dev/v1/query
{
  "package": {"name": "my-dep", "ecosystem": "crystal-shards"},
  "version": "1.2.3"
}
```

**Output example:**
```
🐈‍⬛ [SCA] High  my-dep 1.2.3 → upgrade to 1.2.5
    CVE-2024-12345: Remote code execution via deserialization
```

**Files to create/modify:**
- `src/cli/sca.nim` — SCA module (manifest detection, parsing, OSV query, reporting)
- `src/cli/catseye.nim` — integrate SCA scan into main pipeline

**Notes:**
- OSV supports `crystal-shards` and `hex` (Erlang/Gleam) ecosystems
- Should be opt-in via `--sca` flag or config `[sca] enabled = true`
- Cache OSV results locally for offline/repeat scans
- Rate-limit queries (batch multiple deps per request)

### Task: Conditional taint refinement
**Goal:** `if validator.is_valid(x)` on true branch → clear taint
**Approach:** Detect `if`/`case` nodes with validator calls, mark subsequent code as sanitized

### Task: Language extractors: Ruby, Python, Elixir

### Task: IDE/LSP integration

### Task: Dataflow graph visualization

## Completed (archive to planning/archive/)

### Task: Extractor field-level taint ✅
### Task: File-level scope isolation ✅
### Task: Config bridge wiring ✅
