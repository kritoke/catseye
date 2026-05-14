# OCaml Rewrite Tasks

## Engine Review Phase

### Research Tasks

- [ ] **Benchmark current system**: Profile catseye on largest known Crystal codebase, identify where time is spent
  - Run `time just scan-crystal-all <large-project>` 
  - Add instrumentation to Nim CLI to measure: file discovery, Crystal extraction total, Gleam extraction total, engine time
  - Output: timing breakdown in seconds per phase

- [ ] **Research Semgrep taint analysis**
  - Study: https://semgrep.dev/docs/taint-traces/
  - Compare: Semgrep's taint rule format vs Catseye's rule format
  - Identify: Any patterns Catseye is missing
  - Contact: Semgrep Slack/Discord if questions

- [ ] **Research CodeQL taint tracking**
  - Study: CodeQL documentation on taint tracking
  - Compare: CodeQL's taint tracking model vs Catseye
  - Identify: Any patterns Catseye is missing

- [ ] **Evaluate OCaml tree-sitter bindings**
  - Install `opam install tree-sitter`
  - Test: Parse a Gleam file with tree-sitter-ocaml
  - Document: Any gaps vs Nim's tree-sitter CLI approach

### Prototype Tasks

- [ ] **Prototype OCaml TaintDB with Map**
  - Create `planning/ocaml-rewrite/proto/taint_db.ml`
  - Implement: `seed_sources`, `propagate`, `is_tainted` using `Map.Make(String)`
  - Test against existing Gleam taint.gleam logic on sample files
  - Compare outputs: should be identical

- [ ] **Prototype vulnerability graph**
  - Create `planning/ocaml-rewrite/proto/graph.ml`
  - Implement: `VulnNode`, `VulnEdge`, `build_finding_flow` using graph
  - Test: Does graph correctly represent linear flow findings?

- [ ] **Prototype CLI skeleton**
  - Create minimal OCaml dune project with Cmdliner argument parsing
  - Test: `catseye --help` output
  - Verify: same command-line interface as current Nim CLI

### Decision Tasks

- [ ] **Decide: Map vs List TaintDB**
  - Based on prototype: Does Map preserve semantics?
  - Document: Any edge cases found

- [ ] **Decide: Incremental vs Batch analysis**
  - Based on benchmark: Is incremental worth the complexity?
  - Document: Reasoning

- [ ] **Decide: Worker pool configuration**
  - Based on benchmark: How many Crystal workers?
  - Document: Pool size recommendation

---

## Implementation Phases (Post-Review)

### Phase 1: CLI Skeleton + Crystal Binary

- [ ] Add OCaml to flake.nix devShell
- [ ] Create `catseye-ocaml/` Dune workspace structure
- [ ] Implement file discovery in OCaml
- [ ] Implement args parsing with Cmdliner
- [ ] Build Crystal extractor as pre-compiled binary (`crystal build --release`)
- [ ] Verify: CLI accepts same arguments as current Nim CLI

### Phase 2: OCaml Gleam Extractor

- [ ] Port `gleam_extractor.nim` logic to OCaml
- [ ] Use tree-sitter OCaml bindings
- [ ] Verify: Output matches current Nim extractor JSON format
- [ ] Run: Existing test suite passes

### Phase 3: OCaml Taint Engine

- [ ] Port `taint.gleam` → `taint.ml`
- [ ] Port `rules.gleam` → `rules.ml`
- [ ] Port all rule files (10 rules)
- [ ] Verify: Outputs match current Gleam engine
- [ ] Implement: `ocamlgraph`-based vulnerability graph

### Phase 4: Graph Output + SARIF

- [ ] Implement graph-to-SARIF conversion
- [ ] Implement graph-to-terminal visualization
- [ ] Implement graph-to-Markdown report
- [ ] Verify: SARIF 2.1.0 compliance

### Phase 5: Crystal Worker Pool

- [ ] Implement `CrystalWorker` module
- [ ] Test: Pool of 2 processes
- [ ] Test: Pool of 4 processes
- [ ] Stress test: Large codebase scanning

### Phase 6: Full Integration

- [ ] Run full test suite against OCaml implementation
- [ ] Compare: Current Gleam outputs vs OCaml outputs on real codebases
- [ ] Decision: Retire Nim + Gleam system

---

## Notes

- Tasks marked [ ] are pending
- Implementation phases start only after engine review is complete
- This file will be split into more granular task files as needed