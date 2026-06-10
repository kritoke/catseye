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

### Svelte (11 rules)

| Rule ID                          | What it catches                                                   |
| -------------------------------- | ----------------------------------------------------------------- |
| `svelte4-store`                  | Svelte 4 `writable()`/`readable()`/`derived()` stores — use runes |
| `svelte4-store-pattern`          | Svelte 4 store patterns (subscribe, update)                       |
| `svelte4-event-dispatcher`       | `createEventDispatcher` — Svelte 5 uses callback props            |
| `svelte4-lifecycle`              | `beforeUpdate`/`afterUpdate` — use `$effect()`                    |
| `svelte-xss`                     | `{@html}` with dynamic content                                    |
| `dom-xss`                        | `innerHTML`/`document.write` with dynamic content                 |
| `framework-xss`                  | React/Vue/Angular XSS patterns in Svelte                          |
| `hallucinated-method`            | React hooks (`useState`), Vue directives (`v-if`) in Svelte       |
| `svelte5-state-missing-init`     | `$state()` without initial value                                  |
| `svelte5-effect-missing-cleanup` | `$effect` with `setInterval`/`setTimeout` without cleanup         |
| `svelte5-derived-reassignment`   | Assignment to `$derived` variable (read-only)                     |
| `tick-usage`                     | `tick()` overuse — often unnecessary                              |

### OCaml (18 rules)

| Category                   | Rule ID                    | What it catches                                          |
| -------------------------- | -------------------------- | -------------------------------------------------------- |
| **Hallucinated functions** | `hallucinated-method`      | Haskell/Scala/Python APIs (`foldl`, `putStrLn`, `range`) |
| **Unsafe operations**      | `unsafe-obj-magic`         | `Obj.magic` — unsafe type coercion                       |
|                            | `unsafe-obj`               | `Obj.set_field`, `Obj.truncate` — unsafe mutation        |
|                            | `unsafe-deserialization`   | `Marshal.from_channel`, `Marshal.from_string`            |
|                            | `unsafe-serialization`     | `Marshal.to_channel` — binary serialization risks        |
|                            | `command-injection`        | `Sys.command`, `Sys.chdir` with untrusted input          |
|                            | `command-exec`             | `Unix.exec*` family — replaces current process           |
|                            | `unchecked-file-access`    | File I/O without permission checking                     |
| **Partial functions**      | `partial-function`         | `List.hd`, `List.tl`, `List.assoc`, `Option.get`         |
| **Common mistakes**        | `exception-usage`          | `failwith`, `raise` — prefer `Result.t`                  |
|                            | `bounds-check`             | `Array.get`/`String.get` without bounds checking         |
|                            | `format-string`            | Printf format string issues                              |
| **Best practices**         | `ocaml-verbose-option`     | Nested `match` on options → use `let*`                   |
|                            | `ocaml-non-tail-recursive` | Recursive functions without tail optimization            |
|                            | `ocaml-redundant-if-bool`  | `if x then true else false` → just `x`                   |
|                            | `unused-binding`           | `let` bindings that are never used                       |
|                            | `hardcoded-secrets`        | API key patterns in source code                          |
|                            | `todo-in-code`             | `TODO`/`FIXME` in production code                        |

### Crystal (45 detectors)

| Rule                         | What it catches                                               |
| ---------------------------- | ------------------------------------------------------------- |
| `hallucinated-stdlib`        | Calls to methods that don't exist in Crystal standard library |
| `hardcoded-secrets`          | API key patterns (Stripe, GitHub, AWS, JWT, Slack)            |
| `hardcoded-urls`             | Hardcoded http:// and IP addresses                            |
| `deprecated-syntax`          | `puts`, `p`, `pp` in production code                          |
| `sequential-blocking`        | 3+ sequential HTTP/DB/File blocking calls in a function       |
| `string-concat-loop`         | String concatenation inside iterator blocks                   |
| `nilable-ivar-access`        | Instance variable accesses that may need nil checks           |
| `callback-hell`              | Deeply nested callbacks (3+ levels)                           |
| `blanket-rescue`             | Rescue without specific exception type                        |
| `complex-conditional`        | Complex boolean expressions in conditionals                   |
| `data-clump`                 | 3+ parameters always passed together                          |
| `empty-catch`                | Empty rescue blocks                                           |
| `feature-envy`               | Methods calling another class 5+ times                        |
| `flag-argument`              | Boolean parameters that control method behavior               |
| `float-equality`             | Direct float equality comparisons                             |
| `global-variable`            | `$GLOBAL` variable usage                                      |
| `ignored-return`             | Discarding return values that may indicate errors             |
| `infinite-recursion`         | Recursive calls without base case                             |
| `magic-string`               | Unnamed string constants in conditionals                      |
| `manual-loop`                | Manual while/loop where iterators exist                       |
| `message-chain`              | Method chains ≥ 5 links                                       |
| `missing-else`               | If without else branch (potential logic gap)                  |
| `nested-ternary`             | Nested ternary operators                                      |
| `nil-chaser`                 | Excessive nil checks in chain                                 |
| `open-rescue`                | Rescue without specific exception type                        |
| `primitive-obsession`        | Using primitives instead of domain types                      |
| `redundant-conversion`       | Unnecessary type conversions                                  |
| `redundant-self`             | Unnecessary `self.` prefix                                    |
| `string-interpolation-query` | String interpolation in SQL-like contexts                     |
| `too-many-params`            | Functions with 5+ parameters                                  |
| `type-checker-abuse`         | Overuse of `is_a?`/`responds_to?` checks                      |
| `unreachable-code`           | Code after return/raise/break                                 |
| `unsafe-pointer`             | Pointer arithmetic or unsafe operations                       |
| `debug-print`                | Debug print statements left in code                           |
| `debug-require`              | Development-only requires in production                       |
| `duplicate-validation`       | Repeated validation rules                                     |
| `empty-string-comparison`    | Comparing to `""` instead of `.empty?`                        |
| `long-method`                | Methods exceeding 30 body nodes                               |
| `negated-comparison`         | Double negation or confusing negated comparisons              |
| `reassignment-in-condition`  | Variable reassignment inside conditional                      |
| `repeated-regex`             | Same regex pattern repeated multiple times                    |
| `sleep-in-prod`              | `sleep` calls in production code                              |
| `dead-code-after-error`      | Code after raise/error that can never execute                 |
| `hardcoded-port`             | Hardcoded port numbers                                        |

### Gleam (36 detectors)

| Rule                      | What it catches                                                        |
| ------------------------- | ---------------------------------------------------------------------- |
| `panic-call`              | `panic` used instead of `Result`                                       |
| `list-wrap-unnecessary`   | `List.wrap` on collections                                             |
| `unused-let`              | Bindings that appear unused (note: some are used by runtime)           |
| `useless-let-binding`     | Let bindings with identical value                                      |
| `guard-after-wildcard`    | Guard clauses after wildcard patterns                                  |
| `tuple-abuse`             | Tuples with >3 elements (use named records)                            |
| `non-exhaustive-case`     | Case expressions with only one branch                                  |
| `nested-case`             | Case nested >2 levels deep                                             |
| `redundant-single-case`   | Single-branch case expressions                                         |
| `use-candidate`           | 3+ nested anonymous functions — suggest `use`                          |
| `debug-in-library`        | `io.debug` in non-example/test code                                    |
| `result-in-map`           | `list.map` on Result values                                            |
| `pipeline-steps-overload` | 5+ step pipelines                                                      |
| `list-flatten-singleton`  | Unnecessary `List.flatten`                                             |
| `todo-with-message`       | Bare `todo` without message                                            |
| `implicit-return-discard` | Last expression in function discarded implicitly                       |
| `hardcoded-secrets`       | API key patterns in source code                                        |
| `todo-in-code`            | `TODO`/`FIXME` in production code                                      |
| `assert-density`          | Too many `assert` statements (suggest proper test framework)           |
| `bool-return-check`       | Functions returning bool unnecessarily                                 |
| `deprecated-result-check` | Using deprecated result checking patterns                              |
| `discard-result`          | Discarding Result values without handling                              |
| `equals-true`             | Explicit `== True` comparison (redundant)                              |
| `hallucinated-or-default` | Non-existent Gleam function in `option.or_else` pattern                |
| `hallucinated-to-list`    | Non-existent `to_list` method (Gleam uses `to_list` on specific types) |
| `ignored-result`          | Result values ignored without handling                                 |
| `int-float-division`      | Integer division when float was expected                               |
| `let-assert`              | `let assert` in non-test code (panics on failure)                      |
| `let-assert-on-result`    | `let assert` on Result type (should use `use`)                         |
| `nested-function`         | Nested function definitions (consider extracting)                      |
| `repeated-string-literal` | Same string literal repeated multiple times                            |
| `shadow-variable`         | Variable shadowing in nested scopes                                    |
| `string-concat-chain`     | Long string concatenation chains                                       |
| `typescript-interface`    | TypeScript-style interface patterns in Gleam                           |
| `var-keyword`             | JavaScript `var` keyword detection                                     |

### Rust (3 detectors)

| Rule                | What it catches                                                |
| ------------------- | -------------------------------------------------------------- |
| `RustHallucination` | Python/Ruby/Go APIs in Rust (`len()`, `range()`, `dict.get()`) |
| `UnsafePanic`       | `unwrap()`, `expect()`, `panic!()` without error handling      |
| `RustInefficiency`  | Unnecessary clones, `String::from(&var)`                       |

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

### F# (basic)

F# analysis uses F# Compiler Service (FCS) via an external extractor. The first slice covers:

- **Security**: taint sources (`Console.ReadLine`, `Environment.GetCommandLineArgs`), taint sinks (`File.WriteAllText`, `Process.Start`, `printfn`), skip calls (`ignore`, `failwith`)
- **Code smells**: F# flows through the same AST-based detectors as other languages (complexity, nesting, dead code, etc.)
- **AI antipatterns**: not yet supported for F#

See `src/extractor/fsharp/README.md` for the wire format spec.

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
