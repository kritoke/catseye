# Queue-Based CFG Builder — Specification

**Change:** `openspec/changes/performance-safety`  
**Status:** Proposal  

---

## ADDED Requirements

### Requirement: Queue-based block construction

The CFG builder SHALL use an iterative queue-based algorithm instead of recursive list processing. Each block SHALL be emitted exactly once without list concatenation.

#### Scenario: Linear function body
- **WHEN** a function body contains only assignment and call nodes (no branches)
- **THEN** `build_cfg` produces a single block containing all nodes
- **AND** the algorithm runs in O(n) time where n = number of IL nodes

#### Scenario: Function with branches
- **WHEN** a function body contains `ILBranch` nodes
- **THEN** `build_cfg` creates one block per branch (then, else) as separate queue items
- **AND** each block is processed exactly once

#### Scenario: No recursive list prepending
- **WHEN** `build_cfg` processes a block list
- **THEN** no node list is prepended to another list (`@` operator)
- **AND** block accumulation uses `Queue` and `acc.blocks <-` assignment

### Requirement: Single-pass block emission

The builder SHALL emit each block exactly once. A block's nodes are determined once when the block enters the queue, not when it is emitted.

```ocaml
type builder_state = {
  mutable blocks : basic_block list;
  mutable next_id : int;
  pending : il_block Queue.t;
  edges : (int * int) list;  (* src_id → dst_id *)
}

let emit_block (st : builder_state) (nodes : il_node list) (succs : int list) : int
```

#### Scenario: Branch creates merge point
- **WHEN** `ILBranch (cond, then_block, else_block)` is encountered
- **THEN** a merge block is emitted with `[]` nodes and successors `[then_id; else_id]`
- **AND** `then_block` and `else_block` are added to the pending queue

### Requirement: O(1) block lookup

After CFG construction, blocks SHALL be accessible by ID in O(1) using an `IntMap`.

```ocaml
let build_cfg (fn : il_function) : cfg = 
  (* Build blocks list *)
  let blocks = ... in
  (* Build ID→block map *)
  let block_map = List.fold_left (fun m bb ->
    IntMap.add bb.id bb m
  ) IntMap.empty blocks in
  { cfg with cfg_blocks = blocks; cfg_block_map = block_map }
```

#### Scenario: O(1) block access
- **WHEN** `analyze_cfg` needs to access a block by ID
- **THEN** it uses `IntMap.find` (O(log n)) or direct array access (O(1))
- **AND NOT** `List.find` (O(n)) over the block list

### Requirement: Configurable block limit

The builder SHALL reject CFG construction if the total number of blocks exceeds `max_blocks` (default: 500). The function returns an error result instead of building a pathological CFG.

```ocaml
type cfg_error = 
  | TooManyBlocks of { actual : int; limit : int }
  | Timeout of { elapsed_ms : int }

let build_cfg ?(max_blocks = 500) (fn : il_function) : (cfg, cfg_error) result
```

#### Scenario: Function with 1000 branches
- **WHEN** a function contains deeply nested branches (1000+ blocks)
- **THEN** `build_cfg` returns `Error (TooManyBlocks { actual = 1000; limit = 500 })`
- **AND** the caller falls back to flat engine for this function

#### Scenario: Large function completes
- **WHEN** a function has 400 blocks (within limit)
- **THEN** `build_cfg` returns `Ok cfg` with all blocks
- **AND** analysis proceeds normally

### Requirement: Timeout per function

The builder SHALL accept a `timeout_ms` parameter. If construction exceeds this limit, it returns `Error (Timeout { elapsed_ms })`.

```ocaml
let build_cfg ?(timeout_ms = 5000) (fn : il_function) : (cfg, cfg_error) result
```

#### Scenario: Timeout during CFG build
- **WHEN** `build_cfg` runs for more than `timeout_ms`
- **THEN** it raises `Timeout` or returns `Error (Timeout ...)`
- **AND** the analysis falls back to flat engine

### Requirement: Line numbers preserved

Every block SHALL contain the line number of its first node, for accurate finding reporting.

```ocaml
type basic_block = {
  id : int;
  nodes : il_node list;
  successors : int list;
  entry_line : int;   (* line of first node, 0 if empty *)
}
```

#### Scenario: Finding line number
- **WHEN** a tainted sink is found in block B at line 42
- **THEN** the finding reports line 42
- **AND NOT** line 0 or the wrong line

---

## REMOVED Requirements

### Requirement removed: Recursive build_block

The recursive `build_block` function using `take_linear` list splitting is removed. The new queue-based algorithm replaces it.

### Requirement removed: take_linear prepending

The `take_linear` helper that returns `(linear, rest)` with `linear` reconstructed from reversed accumulator is replaced by direct queue processing.

---

## Type Signatures

```ocaml
(* New types in il_types.ml *)

type cfg_error =
  | TooManyBlocks of { actual : int; limit : int }
  | Timeout of { elapsed_ms : int; partial_blocks : int }

type cfg = {
  cfg_fn_name : string;
  cfg_fn_params : string list;
  cfg_entry : int;
  cfg_blocks : basic_block list;
  cfg_block_map : basic_block IntMap.t;  (* NEW: O(1) lookup *)
  cfg_pos : pos;
}

type basic_block = {
  id : int;
  nodes : il_node list;
  successors : int list;
  entry_line : int;  (* NEW: line of first node *)
}

(* New function signatures *)

val build_cfg : ?max_blocks:int -> ?timeout_ms:int -> il_function -> (cfg, cfg_error) result
val build_cfgs : ?max_blocks:int -> ?timeout_ms:int -> il_unit -> (cfg list, cfg_error) result
```

---

## Test Cases

| Test | Input | Expected Output |
|------|-------|-----------------|
| Linear block | Function with 100 assignments, no branches | Single block, 100 nodes |
| Simple if | `if x then a else b; c` | 4 blocks: entry, then, else, merge |
| Nested if | `if a then if b then c else d else e` | 5 blocks with correct nesting |
| Deep nesting | 50 nested ifs | Returns `Error (TooManyBlocks ...)` at limit |
| Timeout | Function with large loops (build stalls) | `Error (Timeout ...)` within timeout_ms |
| Empty function | Function with no body | Single block, 0 nodes |
| Empty then/else | `if x then end` | 2 blocks: entry (no else), merge |

---

## File Changes

| File | Change |
|------|--------|
| `src/ocaml/lib/catseye_il/il_types.ml` | Add `cfg_error`, `cfg_block_map`, `entry_line` to basic_block |
| `src/ocaml/lib/catseye_il/cfg_builder_v2.ml` | **New** — queue-based builder |
| `src/ocaml/lib/catseye_il/cfg_taint.ml` | Use `cfg.cfg_block_map` for O(1) lookup |
| `src/ocaml/lib/catseye_cli/args.ml` | Add `--cfg-max-blocks`, `--cfg-timeout-ms` |
| `src/ocaml/lib/catseye_cli/config.ml` | Add corresponding config fields |

---

## Backward Compatibility

- Existing `cfg_builder.ml` is kept alongside `cfg_builder_v2.ml` during migration
- `catseye_il` library exports both until v2 is proven
- `--cfg` flag behavior changes: now uses v2 with timeout/fallback instead of hanging