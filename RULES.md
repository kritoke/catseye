# Catseye Rule Reference

**Complete list of security rules, code smells, and AI antipatterns detected by Catseye.**

For configuration options, see [README.md](README.md#configuration).

---

## Security Rules (Taint-Based)

Security rules use taint tracking to detect when user-controlled data reaches dangerous sinks.

### Crystal Security Rules

| Rule                 | Severity | Sinks                                                                                                             | Sources                                                |
| -------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| **SSRF**             | Critical | `HTTP::Client.{get,post,put,patch,delete,exec}`, `client.*`, `Crest::{Request.execute,get,post,put,delete,patch}` | `url`, `params.url`, `user_url`, `query`               |
| **CommandInjection** | Critical | `system`, `Process.run`, `os.command`, `os.cmd`, `shell.cmd`, `cmd.run`, `erlexec.Shell`                          | `cmd`, `command`, `input`, `argv`                      |
| **PathTraversal**    | High     | `File.{read,write,delete,open}`, `Dir.glob`, `Dir.entries`, `simplifile.{read,write,delete}`                      | `path`, `file`, `filename`                             |
| **SQLInjection**     | Critical | `db.{exec,query,scalar,query_one,query_all,execute}`, `database.{exec,query}`                                     | `params`, `request`, `body`                            |
| **OpenRedirect**     | Medium   | `redirect_to`, `response.redirect`, `send_redirect`                                                               | `params`, `url`, `request`                             |
| **LDAPInjection**    | High     | `LDAP.search`, `LDAP.query`, `ldap.search`, `ldap.bind`                                                           | `params`, `filter`, `query`                            |
| **EnvInjection**     | High     | `ENV.[]=`, `ENV.delete`, `ENV.update`                                                                             | `env`, `ENV`, `input`                                  |
| **ScentLeakage**     | Critical | `Logger.{info,warn,error,debug}`, `Log.{info,warn,error}`, `puts`, `print`, `STDOUT.puts`, `STDERR.puts`          | `password`, `token`, `secret`, `api_key`, `credential` |
| **MissingTimeout**   | Medium   | `HTTP::Client.new`, `HTTP::Client.start`                                                                          | —                                                      |
| **WeakCryptography** | Medium   | `Digest::MD5`, `Digest::SHA1`                                                                                     | `password`, `hash`, `digest`                           |
| **InsecureRandom**   | Low      | `Random::Secure`, `int.random`, `float.random`, `list.random`                                                     | —                                                      |
| **HardcodedSecrets** | High     | `password=`, `secret=`, `api_key=`, `token=`, `apikey=`, `access_token=`                                          | —                                                      |
| **ReDoS**            | Medium   | `Regex.new`, `Regex.compile`                                                                                      | `pattern`, `regex`                                     |

### JavaScript / TypeScript Security Rules

| Rule                   | Severity | Sinks                                                                                   | Sources                       |
| ---------------------- | -------- | --------------------------------------------------------------------------------------- | ----------------------------- |
| **CommandInjection**   | Critical | `child_process.$exec`, `child_process.$execSync`, `$spawn`, `$spawnSync`                | `cmd`, `command`, `input`     |
| **PathTraversal**      | High     | `$readFile`, `$writeFile`, `$unlink`, `$readdir`, `fs.readFileSync`, `fs.writeFileSync` | `path`, `file`, `filename`    |
| **EvalInjection**      | Critical | `eval`, `Function`, `setTimeout`, `setInterval` (string arg)                            | `code`, `script`, `input`     |
| **PrototypePollution** | High     | `$merge`, `Object.assign` (with `__proto__`), deep merge with user keys                 | `obj`, `params`, `input`      |
| **XSS**                | Critical | `innerHTML`, `document.write`, `insertAdjacentHTML`                                     | `html`, `content`, `userHtml` |
| **OpenRedirect**       | Medium   | `$redirect`, `location.assign`, `location.href`, `Router.push`                          | `url`, `next`, `redirect`     |
| **WeakCryptography**   | Medium   | `crypto.createHash('md5')`, `crypto.createHash('sha1')`                                 | `password`, `hash`            |
| **InsecureRandom**     | Low      | `Math.random`                                                                           | —                             |

### Svelte Security Rules

| Rule     | Severity | Sinks                                    | Sources           |
| -------- | -------- | ---------------------------------------- | ----------------- |
| **XSS**  | Critical | `{@html}`, `innerHTML`, `document.write` | `html`, `content` |
| **SSRF** | Critical | `$fetch`, `$get`, `$post`, `fetch()`     | `url`, `href`     |

### Rust Security Rules

| Rule                 | Severity | Sinks                                           | Sources          |
| -------------------- | -------- | ----------------------------------------------- | ---------------- |
| **RustUnsafeBlock**  | High     | `unsafe { }`                                    | —                |
| **CommandInjection** | Critical | `Command::new`, `Command::arg`, `Command::args` | `cmd`, `command` |
| **PathTraversal**    | Medium   | `fs::read`, `fs::read_to_string`, `fs::write`   | `path`, `file`   |

### Cross-Language Security Rules

| Rule                        | Severity | Languages   | Sinks                                                 |
| --------------------------- | -------- | ----------- | ----------------------------------------------------- |
| **InsecureDeserialization** | High     | Crystal, JS | `JSON.parse`, `YAML.parse`, `Marshal.load`, `Oj.load` |

---

## Code Smells (`--claws`)

All 16+ code smell detectors analyze AST structure across all supported languages.

### Complexity & Structure

| Detector              | Rule ID             | Threshold                  | Languages |
| --------------------- | ------------------- | -------------------------- | --------- |
| Cyclomatic complexity | `HighComplexity`    | M ≥ 10                     | All       |
| Long parameter list   | `LongParameterList` | ≥ 5 params                 | All       |
| Deep nesting          | `DeepNesting`       | ≥ 4 levels                 | All       |
| Long method           | `LongMethod`        | ≥ 30 body nodes            | All       |
| Complex match         | `ComplexMatch`      | ≥ 5 branches               | All       |
| Spaghetti code        | `SpaghettiCode`     | ≥ 60 body nodes            | All       |
| Large class           | `LargeClass`        | > 500 LOC                  | All       |
| Blob                  | `Blob`              | > 15 methods + data clumps | All       |

### Code Quality

| Detector      | Rule ID        | Threshold                      | Languages |
| ------------- | -------------- | ------------------------------ | --------- |
| Dead code     | `DeadCode`     | unreachable after return/raise | All       |
| God object    | `GodObject`    | ≥ 20 definitions/file          | All       |
| Lazy class    | `LazyClass`    | < 3 methods                    | All       |
| Message chain | `MessageChain` | ≥ 5 method chains              | All       |
| Data class    | `DataClass`    | 2+ props, no behavior          | All       |
| Data clump    | `DataClump`    | 3+ params always together      | All       |
| Flag argument | `FlagArgument` | boolean parameters             | All       |

### Design Smells

| Detector             | Rule ID               | Threshold                   | Languages |
| -------------------- | --------------------- | --------------------------- | --------- |
| Hub-like module      | `HubLikeModule`       | > 12 dependencies           | All       |
| Shotgun surgery      | `ShotgunSurgery`      | 5+ calls to same module     | All       |
| Feature envy         | `FeatureEnvy`         | excessive cross-class calls | All       |
| Parallel inheritance | `ParallelInheritance` | same-prefix hierarchies     | All       |

### Crystal-Specific

| Detector       | Rule ID         | Threshold                      | Languages |
| -------------- | --------------- | ------------------------------ | --------- |
| DRY violation  | `DRYViolation`  | 4+ duplicates                  | Crystal   |
| Orphaned spawn | `OrphanedSpawn` | `spawn` without rescue         | Crystal   |
| Muted pack     | `MutedPack`     | `Channel.send` without receive | Crystal   |
| Dead letter    | `DeadLetter`    | `Channel.close` before receive | Crystal   |

### Inheritance Smells

| Detector                      | Rule ID                     | Threshold                        | Languages |
| ----------------------------- | --------------------------- | -------------------------------- | --------- |
| Deep inheritance              | `DeepInheritance`           | > 4 levels                       | All       |
| Tradition breaker             | `TraditionBreaker`          | > 10 subclasses                  | All       |
| Refused parent bequest        | `RefusedParentBequest`      | > 70% method overrides           | All       |
| Base class should be abstract | `BaseClassShouldBeAbstract` | non-leaf inherited, not abstract | All       |
| Speculative generality        | `SpeculativeGenerality`     | unused interfaces/dead classes   | All       |

---

## AI Antipattern Detection (`--ai-lint`)

Catches patterns common in AI-generated code.

### JavaScript / TypeScript (60+ rules)

| Category                 | Examples                                                                                                      | What it catches                |
| ------------------------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| **Hallucinated methods** | `strip()` → `.trim()`, `len()` → `.length`, `append()` → `.push()`, `print()` → `console.log()`               | Methods that don't exist in JS |
| **Framework confusion**  | Python (`dict`, `range`, `enumerate`), Ruby (`puts`, `select`), Java (`System.out.println`), PHP (`var_dump`) | Wrong language APIs            |
| **Security**             | `eval()`, `new Function()`, `child_process.exec()`, `__proto__`                                               | Security antipatterns          |
| **Best practices**       | `alert()`, `debugger`, `console.log` in production, `document.write()`                                        | Code quality issues            |
| **Code quality**         | `==` instead of `===`, deep `.then()` chains (4+), incomplete `.replace()`                                    | Style violations               |

### Svelte (40+ rules)

| Category                     | Examples                                                                                                      | What it catches      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------- |
| **Svelte 4→5 migration**     | `createEventDispatcher` → callback props, `beforeUpdate`/`afterUpdate` → `$effect()`, Svelte 4 stores → runes | Migration warnings   |
| **Svelte 5 Rune Validation** | `$state()` without init, `$effect` without cleanup, `$derived` reassignment                                   | Rune misuse          |
| **Framework confusion**      | React hooks (`useState`, `useEffect`), Vue directives (`v-if`, `v-for`, `v-model`), Angular (`ngModel`)       | Wrong framework APIs |
| **XSS**                      | `{@html}` with dynamic content                                                                                | Security issue       |

### OCaml (55+ rules)

| Category                   | Examples                                                                                                                    | What it catches        |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| **Hallucinated functions** | Haskell: `foldl` → `List.fold_left`, `putStrLn` → `print_endline`. Scala: `println`, `asInstanceOf`. Python: `range`, `len` | Wrong language APIs    |
| **Unsafe operations**      | `Obj.magic`, `Obj.set_field`, `Marshal.from_channel`, `Sys.command`                                                         | Unsafe code            |
| **Common mistakes**        | `Option.get` (raises on None), `List.hd`/`List.tl` (partial), `Hashtbl.find` (raises Not_found)                             | Partial function usage |
| **Best practices**         | `failwith`/`raise` → `Result.t`, Printf without `open Printf`                                                               | Style violations       |

### Crystal (37-entry database)

| Rule                  | What it catches                                               |
| --------------------- | ------------------------------------------------------------- |
| `hallucinated-stdlib` | Calls to methods that don't exist in Crystal standard library |
| `hardcoded-secrets`   | API key patterns (Stripe, GitHub, AWS, JWT, Slack)            |
| `hardcoded-urls`      | Hardcoded http:// and IP addresses                            |
| `deprecated-syntax`   | `puts`, `p`, `pp` in production code                          |

### Gleam (15 detectors)

| Rule                     | What it catches                                              |
| ------------------------ | ------------------------------------------------------------ |
| `panic-call`             | `panic` used instead of `Result`                             |
| `list-wrap-unnecessary`  | `List.wrap` on collections                                   |
| `unused-let`             | Bindings that appear unused (note: some are used by runtime) |
| `guard-after-wildcard`   | Guard clauses after wildcard patterns                        |
| `tuple-abuse`            | Tuples with >3 elements (use named records)                  |
| `non-exhaustive-case`    | Case expressions with only one branch                        |
| `nested-case`            | Case nested >2 levels deep                                   |
| `redundant-single-case`  | Single-branch case expressions                               |

### Rust (4 detectors)

| Rule                   | What it catches                                                |
| ---------------------- | -------------------------------------------------------------- |
| `HallucinatedFunction` | Python/Ruby/Go APIs in Rust (`len()`, `range()`, `dict.get()`) |
| `UnsafePanic`          | `unwrap()`, `expect()`, `panic!()` without error handling      |
| `RustInefficiency`     | Unnecessary clones, `String::from(&var)`                       |
| `TodoFound`            | `TODO`/`FIXME` in production code                              |

---

## Taint Sources

Data that is automatically considered tainted (user-controlled):

| Source                                                           | Languages      |
| ---------------------------------------------------------------- | -------------- |
| `params`, `request`, `req`, `get_body`, `query`, `io.get_line`   | Crystal, Gleam |
| `url`, `user_url`, `href`, `uri`                                 | Crystal        |
| `body`, `data`, `msg`, `message`, `headers`, `cookie`, `session` | All            |
| `event`, `payload`, `input`, `env`, `ARGV`, `STDIN`, `gets`      | All            |
| Form fields: `form`, `form_data`, `raw_params`                   | All            |

## Known Sanitizers

Functions that neutralize taint:

| Sanitizer                                                      | Effect                      |
| -------------------------------------------------------------- | --------------------------- |
| `URI.parse`, `URI.encode`, `URI.decode`                        | URL encoding/decoding       |
| `Path.posix`, `Path.basename`, `Path.dirname`                  | Safe path extraction        |
| `String.strip`, `String.trim`, `String.slice`                  | String sanitization         |
| `Digest::MD5.hexdigest`, `Digest::SHA256.hexdigest`            | Hashing (deterministic)     |
| `File.expand_path`                                             | Safe path resolution        |
| `check_ssrf`, `validate_url`, `allowlisted_url?`, `valid_url?` | URL validation              |
| `validator.*`, `sanitize.*`, `escape.*`, `encode.*`            | Any validation function     |
| `validate_` (prefix)                                           | Any validation function     |
| `get_or_fetch`                                                 | Safe retrieval              |
| `Random::Secure`, `Tempfile`, `Dir.mktmpdir`                   | Safe random/temp generation |

---

## Quick Reference

```bash
# Scan with security rules only
catseye --rules src/ocaml/rules src/

# Scan with code smells
catseye --claws src/

# Scan with AI antipatterns
catseye --ai-lint src/

# Scan with everything
catseye --rules src/ocaml/rules --claws --ai-lint --cfg src/

# Suppress specific rules
catseye --suppress unused-let,InsecureRandom src/
```
