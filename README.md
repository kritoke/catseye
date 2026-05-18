# Catseye

**Multi-language static security analysis with taint tracking, code smell detection, and AI antipattern linting.**

Supports **Crystal, Gleam, JavaScript, TypeScript, Svelte, and OCaml** — with language-specific security rules and antipattern databases for each.

> **v0.4.2** - Path sensitivity, multi-language anti-patterns, property taint propagation

## Requirements

- **OCaml** 5.x + **Dune** 3.x
- **tree-sitter** + language grammars (JS, TS, Svelte, OCaml, Gleam)
- **Crystal** 1.x (optional — needed only for Crystal language extraction)
- **just** (task runner)
- OCaml libs: yojson, cmdliner, bos, rresult, logs, fmt, toml, kdl, ocamlgraph

The easiest way to get all of these is `nix develop` (see [flake.nix](flake.nix) for the full dev shell). All tree-sitter grammars are included and configured automatically.

## Quick Start

```bash
# With Nix (handles all dependencies including tree-sitter grammars)
nix develop

# Build
just build

# Scan a project (auto-detects all languages)
just scan path/to/project/src

# Scan specific languages only
./bin/catseye-ocaml --rules src/ocaml/rules --lang javascript,typescript path/to/project/

# Scan with all checks
just scan-full path/to/project/src

# JSON output
just scan-json path/to/project/src

# Run tests
just test
```

## Supported Languages

| Language   | Extensions                 | Security Rules |               AI Lint                |   Code Smells   | Extractor                      |
| ---------- | -------------------------- | :------------: | :----------------------------------: | :-------------: | ------------------------------ |
| Crystal    | `.cr`                      |  ✅ 12 rules   |     ✅ 37-entry hallucination DB     | ✅ 16 detectors | Crystal extractor + AST bridge |
| Gleam      | `.gleam`                   |  ✅ 12 rules   |           ✅ 12 detectors            | ✅ 16 detectors | tree-sitter                    |
| JavaScript | `.js` `.jsx` `.mjs` `.cjs` |  ✅ 10 rules   | ✅ 60+ hallucinations + antipatterns | ✅ 16 detectors | tree-sitter                    |
| TypeScript | `.ts` `.tsx`               |  ✅ 10 rules   |         ✅ (shares JS rules)         | ✅ 16 detectors | tree-sitter                    |
| Svelte     | `.svelte`                  |  ✅ XSS/SSRF   | ✅ Svelte 4→5 + framework confusion  | ✅ 16 detectors | tree-sitter (two-pass)         |
| OCaml      | `.ml` `.mli`               |    ✅ Basic    |  ✅ 55+ hallucinations + unsafe ops  | ✅ 16 detectors | tree-sitter                    |
| Rust       | `.rs`                      |    🔜 Future   |        ✅ 4 detectors (WASM)        | 🔜 Future      | tree-sitter (WASM)              |

## CLI Reference

```
catseye [options] <directory>

  -f, --format <fmt>         terminal (default), json, sarif, markdown, dot
  -o, --output <path>        write results to file
  -r, --rules <path>         rules directory (default: rules/)
  --config <path>            config file path (default: .catseye.toml in target or parents)
  --lang <lang>              all (default), or comma-separated: crystal,gleam,javascript,typescript,svelte,ocaml
  --no-color                 disable colored output
  --no-cache                 disable extraction cache
  --clear-cache              clear cache and run full scan
  --cache-dir <path>         cache directory (default: .catseye)
  --cfg                      use IL/CFG-based taint engine (more sensitive)
  --no-cfg                   use flat taint engine (default, fewer findings)
  --analysis-timeout <ms>    timeout for analysis phase (0 = disabled)
  --cfg-max-blocks <n>       max blocks per function CFG (default: 500)
  --cfg-timeout-ms <ms>      timeout per function CFG build (default: 5000)
  --predator-vision          enable reachability analysis (live/dormant/safe)
  --crows-nest               enable supply chain audit (Crystal shard.yml + Gleam gleam.toml only; very limited CVE data)
  --claws                    enable code smell detection
  --ai-lint                  enable AI antipattern detection (Gleam, Crystal, Rust)
  --suppress <rules>         comma-separated rule IDs to suppress (e.g., unused-let,InsecureRandom)
  --include-deps             include shard dependencies in scan (Crystal only)
  -p, --parallelism <n>      parallel workers (0 = auto)
  -v, --version              show version
  -h, --help                 show help
```

## What It Detects

### Security Rules (taint-based)

Rules are KDL files — different rule sets per language, all using the same taint engine.

| Rule                   | Severity |           Crystal/Gleam           |              JS/TS               |         Svelte         |
| ---------------------- | -------- | :-------------------------------: | :------------------------------: | :--------------------: |
| **SSRF**               | Critical | `HTTP::Client.get`, `hackney.get` |         `$fetch`, `$get`         |        `$fetch`        |
| **CommandInjection**   | Critical |      `system`, `Process.run`      |      `child_process.$exec`       |           —            |
| **PathTraversal**      | High     |     `File.read`, `File.write`     |    `$readFile`, `$writeFile`     |           —            |
| **SQLInjection**       | Critical |       `db.exec`, `db.query`       |                —                 |           —            |
| **XSS**                | Critical |                 —                 |  `innerHTML`, `document.write`   | `{@html}`, `innerHTML` |
| **OpenRedirect**       | Medium   |           `redirect_to`           |  `$redirect`, `location.assign`  |           —            |
| **PrototypePollution** | High     |                 —                 |    `$merge`, `Object.assign`     |           —            |
| **EvalInjection**      | Critical |                 —                 | `eval`, `Function`, `setTimeout` |           —            |
| **EnvInjection**       | High     |             `ENV[]=`              |                —                 |           —            |
| **LDAPInjection**      | High     |           `LDAP.query`            |                —                 |           —            |
| **ScentLeakage**       | High     |        `puts`, `Log.info`         |          `console.log`           |           —            |
| **ReDoS**              | Medium   |            `Regex.new`            |           `new RegExp`           |           —            |
| **WeakCryptography**   | Medium   |           `Digest::MD5`           |       `createHash('md5')`        |           —            |
| **HardcodedSecrets**   | Medium   |            `password=`            |            `api_key=`            |           —            |

Rules are KDL files in `src/ocaml/rules/` — add your own by creating a `.kdl` file.

### AI Antipattern Detection (`--ai-lint`)

Catches patterns common in AI-generated code: hallucinated method calls, framework confusion, security antipatterns, and best practice violations.

#### JavaScript / TypeScript (60+ rules)

| Category                 | Examples                                                                                                                           |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Hallucinated methods** | `strip()` → `.trim()`, `len()` → `.length`, `append()` → `.push()`, `print()` → `console.log()`                                    |
| **Framework confusion**  | Python (`dict`, `range`, `enumerate`), Ruby (`puts`, `select`, `compact`), Java (`System.out.println`), PHP (`var_dump`, `strlen`) |
| **Security**             | `eval()`, `new Function()`, `child_process.exec()`, prototype pollution (`__proto__`), `Math.random()` for security                |
| **Best practices**       | `alert()`, `debugger`, `console.log` left in code, `document.write()` deprecated                                                   |
| **Code quality**         | `==` instead of `===`, deep `.then()` chains (4+), `escape()`/`unescape()` deprecated, incomplete `.replace()` sanitization        |

#### Svelte (40+ rules)

| Category                 | Examples                                                                                                        |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- |
| **Svelte 4→5 migration** | `createEventDispatcher` → callback props, `beforeUpdate`/`afterUpdate` → `$effect()`, Svelte 4 stores → runes   |
| **Framework confusion**  | React hooks (`useState`, `useEffect`), Vue directives (`v-if`, `v-for`, `v-model`), Angular (`ngModel`, `ngIf`) |
| **XSS**                  | `{@html}` with dynamic content, `innerHTML`, `document.write`                                                   |
| **Antipatterns**         | `tick()` overuse, Svelte 4 store patterns in runes mode                                                         |

#### OCaml (55+ rules)

| Category                   | Examples                                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Hallucinated functions** | Haskell: `foldl` → `List.fold_left`, `putStrLn` → `print_endline`, `getLine` → `read_line`. Scala: `println`, `asInstanceOf`. Python: `range`, `len`, `strip` |
| **Unsafe operations**      | `Obj.magic`, `Obj.set_field`, `Marshal.from_channel`, `Sys.command`                                                                                           |
| **Common mistakes**        | `Option.get` (raises on None), `List.hd`/`List.tl` (partial), `Hashtbl.find` (raises Not_found)                                                               |
| **Best practices**         | `failwith`/`raise` → use `Result.t`, Printf without `open Printf`                                                                                             |

#### Crystal & Gleam

| Rule                    | Languages | What it catches                                       |
| ----------------------- | --------- | ----------------------------------------------------- |
| `hallucinated-stdlib`   | Crystal   | Calls to methods that don't exist (37-entry database) |
| `hardcoded-secrets`     | Both      | API key patterns (Stripe, GitHub, AWS, JWT, Slack)    |
| `hardcoded-urls`        | Crystal   | Hardcoded http:// and IP addresses                    |
| `deprecated-syntax`     | Crystal   | `puts`, `p`, `pp` in production code                  |
| `panic-call`            | Gleam     | `panic` used instead of `Result`                      |
| `list-wrap-unnecessary` | Gleam     | `List.wrap` on collections                            |

#### Rust

| Rule                   | What it catches                                              |
| ---------------------- | -------------------------------------------------------------|
| `HallucinatedFunction` | Python/Ruby/Go APIs in Rust (`len()`, `range()`, `dict.get()`) |
| `UnsafePanic`          | `unwrap()`, `expect()`, `panic!()` without error handling    |
| `RustInefficiency`     | Unnecessary clones, `String::from(&var)`                     |
| `TodoFound`            | `TODO`/`FIXME` in production code                             |

### Code Smells (`--claws`)

All 16 code smell detectors use **AST-native analysis** via `CatseyeAST.t` — they work across all supported languages.

| Detector              | Rule ID               | Threshold                          |
| --------------------- | --------------------- | ---------------------------------- |
| Cyclomatic complexity | `HighComplexity`      | M ≥ 10                             |
| Long parameter list   | `LongParameterList`   | ≥ 5 params                         |
| Deep nesting          | `DeepNesting`         | ≥ 4 levels                         |
| God objects           | `GodObject`           | ≥ 20 defs/file                     |
| DRY violations        | `DRYViolation`        | 4+ duplicates                      |
| Long method           | `LongMethod`          | ≥ 30 nodes                         |
| Message chain         | `MessageChain`        | ≥ 5 links                          |
| Data class            | `DataClass`           | 2+ props, no behavior              |
| Data clump            | `DataClump`           | 3+ params always together          |
| Flag argument         | `FlagArgument`        | bool params                        |
| Complex match         | `ComplexMatch`        | ≥ 5 branches                       |
| Dead code             | `DeadCode`            | unreachable code                   |
| Feature envy          | `FeatureEnvy`         | excessive cross-class calls        |
| Orphaned spawn        | `OrphanedSpawn`       | `spawn`/`go` without rescue/ensure |
| Muted pack            | `MutedPack`           | `Channel.send` without receive     |
| Dead letter           | `DeadLetter`          | `Channel.close` before receive     |
| Spaghetti code        | `SpaghettiCode`       | ≥ 60 body nodes                    |
| Large class           | `LargeClass`          | > 500 LOC                          |
| Blob                  | `Blob`                | large + data clumps                |
| Lazy class            | `LazyClass`           | < 3 methods                        |
| Hub-like module       | `HubLikeModule`       | > 12 dependencies                  |
| Shotgun surgery       | `ShotgunSurgery`      | 5+ calls to same module            |
| Parallel inheritance  | `ParallelInheritance` | same-prefix class hierarchies      |

### Supply Chain Audit (`--crows-nest`)

> ⚠️ **Very limited.** Only supports Crystal `shard.yml` and Gleam `gleam.toml`. No JavaScript/TypeScript (npm/pnpm/yarn), Python, Ruby, Rust, Go, or other ecosystems. CVE data via [OSV.dev](https://osv.dev) has **very limited coverage** — most packages return no vulnerabilities even when known issues exist. Use dedicated tools like `npm audit`, `cargo audit`, or `safety` for real supply chain auditing.

What it does:

- Parses `shard.yml` → Crystal Shards dependencies (with versions from GitHub)
- Parses `gleam.toml` → Gleam Hex dependencies
- Queries OSV.dev for known CVEs (limited data coverage)
- Checks GitHub repo activity for staleness (Crystal shards with `github:` fields)
- Results cached in SQLite (24h TTL)

What it doesn't do:

- Parse `package.json`, `Cargo.toml`, `requirements.txt`, `Gemfile`, etc.
- Run ecosystem-native audit tools (`pnpm audit`, `cargo audit`, etc.)
- Provide comprehensive vulnerability coverage
- Check lockfiles for exact installed versions

## Example Output

```
  Catseye v0.4.2
  Target:   ./src
  Files:    72 Crystal, 8 JavaScript, 5 TypeScript, 4 Svelte

  → Running analysis engine (7367 nodes)...

  🔴 Error  SSRF  src/controllers/proxy_controller.cr:32
       Potential SSRF via HTTP::Client.get with tainted argument(s): url.
      ← Source: params (proxy_controller.cr:28)

  🔴 Error  XSS  frontend/src/routes/+page.svelte:15
       {@html} with dynamic content is an XSS risk — ensure input is sanitized

  [ai:hallucinated-method] scripts/utils.js:42 - 'strip()' doesn't exist in JS — use .trim()

  ⚠️ Warning  PathTraversal  src/file_handler.cr:45
       Path traversal via File.read — but path.starts_with?() validation detected, suppressing.

  Found 6 Error(s), 0 Warning(s) across 89 files.
  Review the findings above.
```

## How It Works

```
Source files
    │
    ├─ Crystal (.cr) ──→ Crystal extractor (AST → JSON) ─┐
    ├─ Gleam (.gleam) ─→ tree-sitter (CST → XML → AST) ─┤
    ├─ JS/TS (.js .ts) ─→ tree-sitter (CST → XML → AST) ┤
    ├─ Svelte (.svelte) ─→ tree-sitter two-pass ─────────┤
    └─ OCaml (.ml) ─→ tree-sitter (CST → XML → AST) ────┤
                                                          │
                              CatseyeAST.t (unified) ◄────┘
                                    │
                   ┌────────────────┼────────────────┐
                   ▼                ▼                ▼
             Security Nodes    AI Linter       Code Smells
             (taint engine)   (AST rules)    (Claws)
                   │                │                │
                   └────────────────┼────────────────┘
                                    ▼
                          KDL Rule Interpreter
                                    │
                          Terminal / JSON / SARIF / Markdown / DOT
```

**Taint pipeline:** seed → propagate → returns → interproc → propagate → cross-file → guards → rules

1. **Seed** — Params named like taint sources (`url`, `request`, `params`) are marked tainted
2. **Propagate** — Fixed-point; taint flows through assignments, call chains, and **property access** (e.g., `uri.request_target` inherits taint from `uri`)
3. **Returns** — Functions with tainted bodies return tainted data
4. **Inter-procedural** — Taint crosses function boundaries
5. **Guards** — `unless path.starts_with?("/safe/")` suppresses taint (**path sensitivity**)
6. **Rules** — KDL rules match sinks against tainted variables, with `arg=N` position matching

**Path sensitivity** reduces false positives by tracking validation guards:

- `starts_with?`, `end_with?` → suppress path traversal
- `valid_url?`, `check_*`, `sanitize_*` → suppress SSRF
- Validation scope: 50 lines or to next function boundary

**CFG engine** (`--cfg`) converts CatseyeAST.t → IL → basic block CFG → forward dataflow taint analysis. Branch-aware: taint does not flow across dead branches. Dominator-based sanitizer suppression.

### Adding a Security Rule

Create `src/ocaml/rules/my_rule.kdl`:

```kdl
rule "MyRule" severity="Medium" {
    sinks {
        sink "Dangerous.call" arg=0 {
            sanitizer "Safe.wrapper"
        }
    }
    sources {
        source "params"
        source "url"
    }
    message "My rule: {sink} with tainted argument(s): {tainted_vars}."
}
```

`arg=0` means only flag when tainted data is in the first argument. Omit for any-arg matching.
`$var` metavariables match any receiver prefix: `sink "$client.get"` matches `http.get`, `conn.get`, `my_client.get`.

Rebuild with `just build` and test.

### Extraction Strategy

**Crystal** uses a dedicated Crystal extractor (compiled at build time). All other languages use **tree-sitter** with language-specific CST → CatseyeAST mappers.

For Crystal projects with `shard.yml`, the `lib/` directory is automatically excluded to skip shard dependencies and avoid symlink loops.

**Svelte** uses a two-pass strategy: first parse with tree-sitter-svelte to extract `<script>` blocks, then parse the script content with the JS/TS grammar.

## Configuration

Optional `.catseye.toml` in your project root (walked up from the target directory):

```toml
[scan]
exclude = ["node_modules", ".git", "vendor", "spec"]

[analysis]
extra_sources = ["user_input", "raw_params"]
extra_sanitizers = ["sanitize_path", "escape_shell"]
parallelism = 4

[claws]
complexity_warning = 10
max_params = 5

# Suppress code smell rules by file glob
[claws.suppress]
DataClump = ["**"]
LongParameterList = ["**/repositories/**"]

# Suppress security/taint findings by file glob
[taint.suppress]
SSRF = ["**/validated_http_client.cr"]
PathTraversal = ["**/safe_io.cr"]

# Suppress specific rules by ID (CLI --suppress flag)
[suppress]
# unused-let: Gleam OTP bindings appear unused but are used by runtime
unused-let = true
guard-after-wildcard = true
```

### CLI Suppress Flag

Use `--suppress` to disable specific rules without a config file:

```bash
catseye ./src --suppress unused-let,guard-after-wildcard

# Suppress security rules
catseye ./src --suppress InsecureRandom,WeakCryptography
```

This suppresses rules in both the taint/security engine and AI lint detectors.

### Glob Patterns

- `*` matches any characters except `/`
- `**` matches any characters including `/` (cross-directory)
- `?` matches a single character

## Justfile Recipes

```
just build               Build the engine
just test                Unit tests + E2E
just scan <dir>          Scan with terminal output
just scan-full <dir>     Scan with all checks enabled
just scan-json <dir>     Scan with JSON output
just scan-ai <dir>       AI antipattern detection only
just scan-reports <dir>  Generate JSON + SARIF + Markdown reports
just fmt                 Format OCaml code
just lint                Check formatting
just clean               Clean build artifacts
just extract <file>      Run Crystal extractor on a single file (debug)
```

## Project Structure

```
catseye/
├── src/
│   ├── ocaml/
│   │   ├── bin/main.ml                 # CLI entry point
│   │   ├── lib/
│   │   │   ├── catseye_engine/          # Flat taint analysis + propagation, extractor registry
│   │   │   ├── catseye_il/              # IL types, CFG builder (ocamlgraph), dominator analysis
│   │   │   ├── catseye_ast/             # Unified AST + language mappers + plugin registry
│   │   │   │   ├── crystal_mapper.ml         # Crystal JSON → AST
│   │   │   │   ├── gleam_mapper.ml           # Gleam tree-sitter → AST
│   │   │   │   ├── javascript_mapper.ml      # JS tree-sitter → AST
│   │   │   │   ├── typescript_mapper.ml      # TS (extends JS mapper)
│   │   │   │   ├── svelte_mapper.ml          # Svelte two-pass → AST
│   │   │   │   ├── ocaml_mapper.ml           # OCaml tree-sitter → AST
│   │   │   │   ├── language_plugin.ml        # Plugin interface
│   │   │   │   └── plugin_registry.ml        # Plugin discovery
│   │   │   ├── ai_linter/              # AI antipattern rules
│   │   │   │   ├── crystal_rules.ml          # Crystal hallucination DB (37 entries)
│   │   │   │   ├── gleam_rules.ml            # Gleam antipatterns
│   │   │   │   ├── javascript_rules.ml       # JS/TS hallucinations + antipatterns (60+)
│   │   │   │   ├── svelte_rules.ml           # Svelte 4→5 + framework confusion (40+)
│   │   │   │   └── ocaml_rules.ml            # OCaml hallucinations + unsafe ops (55+)
│   │   │   ├── catseye_claws/           # Code smell detection (AST-native, 16 detectors)
│   │   │   ├── catseye_crowsnest/       # Supply chain audit
│   │   │   ├── catseye_rules/           # KDL rule interpreter (arg, $var, fix templates)
│   │   │   ├── catseye_cli/             # CLI, orchestrator, output formats
│   │   │   └── catseye_types/           # Shared types
│   │   └── rules/                       # KDL rule files
│   │       ├── crystal/*.kdl                  # Crystal security rules
│   │       ├── javascript.kdl                 # JS/TS security rules
│   │       └── gleam/*.kdl                    # Gleam security rules
│   └── extractor/extractor.cr           # Crystal AST extractor
├── test/samples/                        # Test corpus (Crystal, JS, Svelte)
├── flake.nix                            # Nix dev shell (all grammars)
└── justfile                             # Build tasks
```

## Performance

| Scan                      | Files                        | Extraction | Analysis |
| ------------------------- | ---------------------------- | ---------- | -------- |
| Crystal only (72 files)   | 72                           | ~0.12s     | ~0.06s   |
| Multi-language (89 files) | 72 Crystal + 17 JS/TS/Svelte | ~0.25s     | ~6s      |
| OCaml self-scan           | 84                           | ~0.19s     | ~0.15s   |
| Gleam project (144 files) | 115 Gleam + 29 TS/JS         | ~0.73s     | ~0.14s   |

**CFG engine** scales linearly: 500 sequential branches in 0.09ms, 10,000 nodes in 2.4ms, 500-block taint analysis in 0.75ms.

## License

MIT
