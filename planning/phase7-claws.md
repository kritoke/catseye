# Phase 7: Claws Module — Code Smells & DRY Detection

**Phase:** 7  
**Priority:** High (major new capability)  
**Depends on:** None (independent of Phase 6, can parallel)  
**Parent:** `planning/roadmap.md`  
**Status:** Design complete, ready to implement

---

## Overview

Claws is Catseye's code health module. It detects code smells (complexity, structural issues) and DRY violations (duplicated code blocks) using the same `Security_node.t` stream that Catseye uses for security analysis.

Claws findings use the same Hunter taxonomy:
- **HISS** — Critical smell (complexity > 20, god object)
- **MEOW** — Warning smell (complexity 10–19, long params, deep nesting)
- **PURR** — Clean

---

## Architecture

```
Security_node.t list
        │
        ▼
┌───────────────────────────────────────────────────┐
│                  smells.ml                         │
│  (unified pipeline — orchestrates all detectors)   │
│                                                    │
│   ┌──────────────┐  ┌─────────────┐  ┌─────────┐ │
│   │ complexity.ml │  │ anatomy.ml  │  │ dry.ml  │ │
│   │              │  │             │  │         │ │
│   │ Walk Def     │  │ Walk Def    │  │ Window  │ │
│   │ scopes →     │  │ args, body  │  │ → Norm  │ │
│   │ count        │  │ nesting,    │  │ → Hash  │ │
│   │ decisions    │  │ file method │  │ → Bucket│ │
│   └──────────────┘  └─────────────┘  └─────────┘ │
│                                                    │
│   ┌─────────────────────────────────────────────┐ │
│   │ ameba_hook.ml (optional, Crystal only)       │ │
│   │ Shell out → parse JSON → convert to findings │ │
│   └─────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────┘
        │
        ▼
  Finding.t list (merged with Catseye findings)
```

---

## C1: Dune Library Scaffold

### New Library: `catseye_claws`

```
src/ocaml/lib/catseye_claws/
├── dune
├── types.ml          # Claws-specific types + config
├── complexity.ml     # Cyclomatic complexity detector
├── anatomy.ml        # Structural smell detector
├── dry.ml            # DRY structural hashing
├── ameba_hook.ml     # Ameba linter integration
└── smells.ml         # Unified pipeline
```

**`dune`:**
```lisp
(library
 (name catseye_claws)
 (public_name catseye.claws)
 (modules types complexity anatomy dry ameba_hook smells)
 (libraries catseye.types yojson unix logs))
```

**Dependency:** Only `catseye.types` (for `Security_node.t` and `Finding.t`). No dependency on `catseye_engine` — Claws operates on the same data but is fully decoupled.

### Types (`types.ml`)

```ocaml
type claws_config = {
  (* Complexity *)
  complexity_warning : int;     (* default: 10 *)
  complexity_critical : int;    (* default: 20 *)

  (* Anatomy *)
  max_params : int;             (* default: 5 *)
  max_params_critical : int;    (* default: 8 *)
  max_nesting : int;            (* default: 4 *)
  max_nesting_critical : int;   (* default: 6 *)
  max_methods_per_file : int;   (* default: 20 *)

  (* DRY *)
  dry_enabled : bool;           (* default: true *)
  dry_window_size : int;        (* default: 6 *)
  dry_min_occurrences : int;    (* default: 2 *)

  (* Ameba *)
  ameba_enabled : bool;         (* default: false *)
  ameba_path : string;          (* default: "ameba" *)
}

let default_config = {
  complexity_warning = 10;
  complexity_critical = 20;
  max_params = 5;
  max_params_critical = 8;
  max_nesting = 4;
  max_nesting_critical = 6;
  max_methods_per_file = 20;
  dry_enabled = true;
  dry_window_size = 6;
  dry_min_occurrences = 2;
  ameba_enabled = false;
  ameba_path = "ameba";
}
```

---

## C2: Complexity Walker

### Algorithm

Cyclomatic complexity is approximated by counting **decision points** in a function's node list:

```
M = 1 + (count of decision nodes)
```

Decision nodes identified by pattern matching on Security Node names:

| Pattern | Decision Type | Weight |
|---------|--------------|--------|
| `if`, `unless` | Conditional | 1 |
| `case`, `select`, `when` | Multi-branch | 1 |
| `&&`, `\|\|`, `and`, `or` | Logical combinator | 1 |
| `loop`, `while`, `for`, `each` | Loop | 1 |
| `try`, `rescue` | Exception handling | 1 |

### Scope Building

Each `Def` node defines a function scope. The scope includes all nodes from the Def's line to the next Def in the same file (line-range heuristic, same as `reachability.ml`).

**Decision:** Duplicate the ~30-line scope builder from `reachability.ml` into `complexity.ml`. Avoids a cross-library dependency. The code is small and stable.

### Implementation Sketch

```ocaml
(* complexity.ml *)

let compute_complexity (fn_nodes : Security_node.t list) : int =
  1 + List.fold_left (fun acc n ->
    acc + is_decision n.Security_node.name
  ) 0 fn_nodes

let analyze (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  let scopes = build_scopes nodes in
  List.filter_map (fun (def, body) ->
    let complexity = compute_complexity body in
    let severity =
      if complexity >= config.complexity_critical then "High"
      else if complexity >= config.complexity_warning then "Medium"
      else ""
    in
    if severity = "" then None
    else Some {
      Finding.rule = "HighComplexity";
      severity;
      file = def.Security_node.file;
      line = def.Security_node.line;
      message = Printf.sprintf
        "Function '%s' has cyclomatic complexity of %d (threshold: %d)"
        def.Security_node.name complexity
        (if severity = "High" then config.complexity_critical
         else config.complexity_warning);
      flow = [];
      language = def.Security_node.language;
      dependency = None;
      reachability = None;
    }
  ) scopes
```

### Limitations

- **Approximation, not exact.** Without full AST structure (if/else branches, begin/end blocks), we count occurrences of decision patterns in the flat node list. A function with `if x; if y; end; end` gets M=3 (correct), but we can't distinguish sequential `if`s from nested ones.
- **Overcounting.** A call to `obj.each` counts as +1 even if it's not a control flow construct. The heuristic works well for typical codebases where such names are rare.
- **Mitigation:** The thresholds (10/20) are generous enough to absorb minor overcounting.

---

## C3: Anatomy Walker

### C3a: Long Parameter Lists

Trivially detected: count `Def` node args.

```ocaml
let check_params (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  nodes
  |> List.filter (fun n -> n.Security_node.node_type = Security_node.Def)
  |> List.filter_map (fun def ->
    let count = List.length def.Security_node.args in
    if count >= config.max_params_critical then
      Some (make_finding def "LongParameterList" "High" ...)
    else if count >= config.max_params then
      Some (make_finding def "LongParameterList" "Medium" ...)
    else None
  )
```

### C3b: Deep Nesting

**Challenge:** Security Nodes don't encode nesting structure. The flat node list loses `begin/end` and `do/end` boundaries.

**Pragmatic heuristic:** Count scope-creating patterns within each function:

```ocaml
let scope_creators = ["if"; "unless"; "case"; "do"; "begin"; "try"; "loop"; "while"; "each"]

let approx_nesting_depth (fn_nodes : Security_node.t list) : int =
  List.fold_left (fun acc n ->
    if List.exists (fun p -> is_substring p n.Security_node.name) scope_creators
    then acc + 1
    else acc
  ) 0 fn_nodes
```

This gives a rough upper bound. A function with 3 `if` statements gets nesting=3, even if they're sequential (not nested).

**Better long-term fix:** Extend the Crystal extractor to emit nesting metadata. Add `metadata: {"nesting_depth": "3"}` to each node. This would require tracking the Crystal parser's scope stack depth.

**For Phase 7:** Use the heuristic. Document the limitation. The threshold (4/6) is generous.

### C3c: God Objects

Count Def nodes per file. If a file exceeds `max_methods_per_file`, flag it.

```ocaml
let check_god_objects (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  let file_defs = group_defs_by_file nodes in
  List.filter_map (fun (file, defs) ->
    let count = List.length defs in
    if count >= config.max_methods_per_file then
      Some { Finding.rule = "GodObject"; severity = "Medium";
             file; line = (List.hd defs).Security_node.line;
             message = Printf.sprintf
               "File has %d method definitions (threshold: %d). Consider splitting."
               count config.max_methods_per_file;
             ... }
    else None
  ) file_defs
```

---

## C4: DRY Structural Hashing

### Algorithm

```
INPUT:  Security_node.t list grouped by file
OUTPUT: Finding.t list of DRY violations

Step 1: SLICE
  For each file, create overlapping windows of N consecutive nodes.
  Window size: 6 (default, configurable).
  Skip windows of only Def/Call nodes — want assignment chains.

Step 2: NORMALIZE
  For each window, produce a canonical string:
    Call:   "Call|<name>|<arg_count>"        (preserve API patterns)
    Assign: "Assign|_|<arg_count>"            (strip var name)
    Def:    "Def|_|<arg_count>"               (strip fn name)
    Var:    "Var|_|0"                          (strip var name)
    Literal:"Literal|_|0"
  Join with "|".

Step 3: HASH
  Hashtbl.hash of normalized string → 8-char hex.
  Same approach as cache.ml content addressing.

Step 4: BUCKET
  Group windows by hash into Hashtbl.
  Buckets with ≥2 entries from different (file, line) pairs are violations.

Step 5: REPORT
  One Finding.t per violation bucket:
  - rule: "DRYViolation"
  - severity: "Medium" (always MEOW — code quality)
  - message: "Duplicate code block found in N locations"
  - flow: each location as a flow_step
```

### Normalization Example

```crystal
# File A: src/cache.cr
url = params["url"]
result = HTTP::Client.get(url)
data = JSON.parse(result)

# File B: src/api.cr
endpoint = params["endpoint"]
response = HTTP::Client.get(endpoint)
parsed = JSON.parse(response)
```

Both normalize to identical windows:
```
Window 1: "Assign|_|1|Call|HTTP::Client.get|1|Assign|_|1"
```

This detects copy-paste-with-rename, which is the most common form of code duplication.

### Implementation Sketch

```ocaml
(* dry.ml *)

type window = {
  file : string;
  start_line : int;
  end_line : int;
  nodes : Security_node.t list;
  normalized : string;
  hash : string;
}

(** Generate overlapping windows of size n from a sorted node list. *)
let generate_windows (file : string) (nodes : Security_node.t list) (size : int)
    : window list =
  let arr = Array.of_list nodes in
  let n = Array.length arr in
  if n < size then []
  else begin
    let windows = ref [] in
    for i = 0 to n - size do
      let window_nodes = Array.sub arr i size |> Array.to_list in
      let norm = normalize_window window_nodes in
      let hash = structural_hash norm in
      windows := {
        file;
        start_line = (List.hd window_nodes).Security_node.line;
        end_line = (List.hd (List.rev window_nodes)).Security_node.line;
        nodes = window_nodes;
        normalized = norm;
        hash;
      } :: !windows
    done;
    List.rev !windows
  end

(** Detect DRY violations across all files. *)
let detect (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  (* Group nodes by file *)
  let by_file = group_by_file nodes in
  (* Generate all windows *)
  let all_windows = List.concat_map (fun (file, fnodes) ->
    generate_windows file fnodes config.dry_window_size
  ) by_file in
  (* Bucket by hash *)
  let buckets : (string, window list) Hashtbl.t = Hashtbl.create 256 in
  List.iter (fun w ->
    let existing = try Hashtbl.find buckets w.hash with Not_found -> [] in
    Hashtbl.replace buckets w.hash (w :: existing)
  ) all_windows;
  (* Filter to violations *)
  Hashtbl.fold (fun _hash windows acc ->
    if List.length windows >= config.dry_min_occurrences then begin
      let unique = unique_by_location windows in
      if List.length unique >= config.dry_min_occurrences then
        make_dry_finding unique :: acc
      else acc
    end else acc
  ) buckets []
```

### Performance Considerations

- **Window generation:** O(n × w) where n = total nodes, w = window size. For 5K nodes and w=6, that's 30K windows.
- **Hashing:** O(1) per window (polynomial hash).
- **Bucketing:** O(windows) with Hashtbl.
- **Total:** Linear in total node count. Should be < 50ms for typical codebases.

---

## C5: Unified Pipeline (`smells.ml`)

```ocaml
(* smells.ml *)

(** Run all Claws detectors and return merged findings. *)
let analyze (nodes : Security_node.t list)
    (config : Types.claws_config) : Finding.t list =
  let complexity_findings = Complexity.analyze nodes config in
  let anatomy_findings = Anatomy.analyze nodes config in
  let dry_findings =
    if config.dry_enabled then Dry.detect nodes config
    else []
  in
  let ameba_findings =
    if config.ameba_enabled then Ameba_hook.run config nodes
    else []
  in
  complexity_findings @ anatomy_findings @ dry_findings @ ameba_findings
  |> deduplicate_findings
```

---

## C6: CLI Integration

### Args (`args.ml`)

Add `--claws` flag:

```ocaml
| "--claws" :: rest ->
  go { acc with claws = true } rest
```

### Config (`config.ml`)

Add `claws` field and TOML `[claws]` section:

```ocaml
type t = {
  ...
  claws : bool;
  claws_config : Catseye_claws.Types.claws_config;
}
```

### Orchestrator (`orchestrator.ml`)

After security analysis, if `--claws` is enabled:

```ocaml
(* Step 4d: Claws — code smell analysis *)
let claws_findings = if config.claws then
  Catseye_claws.Smells.analyze nodes config.claws_config
else [] in
let all_findings = reachability @ claws_findings in
```

Claws findings use the same output pipeline (terminal with Hunter persona, JSON, SARIF, Markdown).

---

## C7: Ameba Hook (Optional)

For Crystal projects, delegate to Ameba for idiomatic checks:

```ocaml
(* ameba_hook.ml *)

(** Run Ameba on Crystal files, convert to Finding.t list. *)
let run (config : Types.claws_config) (nodes : Security_node.t list)
    : Finding.t list =
  let crystal_files = List.filter_map (fun n ->
    if n.Security_node.language = "crystal" then Some n.Security_node.file
    else None
  ) nodes |> List.sort_uniq String.compare in
  if crystal_files = [] then []
  else begin
    let cmd = Printf.sprintf "%s --format json %s 2>/dev/null"
      (Filename.quote config.ameba_path)
      (String.concat " " (List.map Filename.quote crystal_files)) in
    let (stdout_ch, stdin_ch, stderr_ch) =
      Unix.open_process_full cmd (Unix.environment ()) in
    let output = Buffer.create 4096 in
    (try while true do Buffer.add_channel output stdout_ch 4096 done
     with End_of_file -> ());
    let _ = Unix.close_process_full (stdout_ch, stdin_ch, stderr_ch) in
    let json = Buffer.contents output in
    parse_ameba_output json
  end
```

Ameba is **optional** — if not in `$PATH`, silently skip.

---

## C8: Test Plan

### Test Files

Create `test/samples/smell_samples/`:

| File | Purpose | Expected Findings |
|------|---------|-------------------|
| `complex.cr` | Function with M=15 | 1 MEOW (HighComplexity) |
| `params.cr` | Function with 7 parameters | 1 MEOW (LongParameterList) |
| `god.cr` | File with 25 methods | 1 MEOW (GodObject) |
| `dry_a.cr` + `dry_b.cr` | Copy-paste blocks | 1 MEOW (DRYViolation) |
| `clean.cr` | Well-structured code | 0 findings (PURR) |

### Exit Criteria

- [ ] `catseye_claws` library builds with `dune build`
- [ ] `--claws` flag activates smell detection
- [ ] Complexity findings appear in terminal + JSON output
- [ ] DRY detects duplicated blocks across files in test corpus
- [ ] God object detection works on files with > 20 methods
- [ ] Performance budget: < 200ms added per 1K nodes
- [ ] No regression in security analysis findings
- [ ] All existing tests pass

---

## Implementation Order

```
C1 (scaffold) → C2 (complexity) → C3 (anatomy) → C5 (pipeline)
                                                  │
                                          C6 (CLI integration)
                                                  │
                                          C4 (DRY — largest, most complex)
                                                  │
                                          C7 (Ameba — optional)
```

C4 (DRY) is the most complex task. Do it last, after the simpler detectors prove the pipeline works.
