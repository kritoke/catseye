# Phase 10: Release & Distribution

**Phase:** 10  
**Priority:** Low (only after Phases 6–9 complete)  
**Depends on:** All prior phases  
**Parent:** `planning/roadmap.md`  
**Status:** Design complete

---

## Overview

Ship Catseye as a polished, distributable static analysis tool. This phase covers binary distribution, CI hardening, user-facing documentation, and package registry publishing.

The release target is **v1.0.0** — the first version considered production-ready for external users.

---

## Current State

### What We Have

| Asset | Status | Notes |
|-------|--------|-------|
| Dynamic ELF binary (aarch64) | ✅ Built | 5.5 MB, dynamically links glibc + sqlite3 + zlib |
| Nix Flake dev shell | ✅ Working | OCaml 5.4, Crystal 1.18, tree-sitter, SQLite |
| GitHub Actions workflow | ✅ Partial | Self-scan only (build → scan → upload SARIF) |
| README.md | ✅ Comprehensive | Architecture, quick start, all features, rule authoring |
| `.catseye.toml` config | ✅ Working | TOML with `[scan]`, `[analysis]`, `[persona]`, `[crows_nest]` |
| 11 KDL rule files | ✅ Production | SSRF, CmdInjection, PathTraversal, SQLInjection, etc. |
| `justfile` build tasks | ✅ Working | build, test, scan, lint, fmt, clean |
| opam-ready dune-project | ✅ Configured | `(generate_opam_files true)` set |

### What's Missing

| Gap | Impact | Task |
|-----|--------|------|
| Binary is dynamically linked | Won't run outside Nix | R1 |
| No CI for PR validation | Broken builds can land on main | R2 |
| Single-arch only (aarch64-linux) | No x86_64, no macOS | R3 |
| No opam publication | Can't `opam install catseye` | R4 |
| No version stamping | Binary reports hardcoded version | R5 |
| No integration test in CI | Regressions caught manually | R6 |
| No release automation | Manual binary uploads | R7 |
| README is developer-focused | Not a user landing page | R8 |

---

## R1: Static Binary Build

### Problem

The current binary dynamically links against Nix store paths:

```
libsqlite3.so => /nix/store/.../lib/libsqlite3.so
libc.so.6     => /nix/store/.../lib/libc.so.6
libz.so.1     => /nix/store/.../lib/libz.so.1
```

This binary will not run on any system without identical Nix store paths.

### Solution

Build a statically linked binary using `musl` as the C library.

#### OCaml Binary

```bash
# In a Nix shell with musl toolchain:
dune build --profile release
ocamlfind ocamlopt -linkpkg -package <all_packages> \
  -ccopt -static bin/main.ml -o bin/catseye
```

**Nix Flake addition** — add a proper package derivation:

```nix
# flake.nix — add to outputs

packages.${system} = {
  catseye = pkgs.stdenv.mkDerivation {
    pname = "catseye";
    version = "1.0.0";

    src = self;

    nativeBuildInputs = with pkgs; [
      ocamlPkgs.ocaml
      ocamlPkgs.dune_3
      ocamlPkgs.findlib
      crystal_1_18
      tree-sitter
      tree-sitter-grammars.tree-sitter-gleam
      just
      musl
    ];

    buildInputs = with ocamlPkgs; [
      yojson toml kdl cmdliner bos rresult logs fmt
      ocaml_sqlite3 ocamlgraph eio eio_posix
    ];

    buildPhase = ''
      # Build Crystal extractor
      crystal build src/extractor/extractor.cr -o bin/catseye-crystal-extractor --release --static

      # Build OCaml engine
      cd src/ocaml
      dune build --profile release
      cd ../..
      cp src/ocaml/_build/default/bin/main.exe bin/catseye
    '';

    installPhase = ''
      mkdir -p $out/bin $out/share/catseye/rules
      cp bin/catseye $out/bin/
      cp bin/catseye-crystal-extractor $out/bin/
      cp -r src/ocaml/rules/*.kdl $out/share/catseye/rules/
    '';
  };
};

defaultPackage.${system} = self.packages.${system}.catseye;
```

#### Crystal Extractor Binary

```bash
crystal build src/extractor/extractor.cr \
  -o bin/catseye-crystal-extractor \
  --release --static
```

Crystal's `--static` flag produces a fully static binary when built with musl.

### Deliverables

| Binary | Target | Expected Size |
|--------|--------|---------------|
| `catseye` | Linux aarch64 (static) | ~6 MB |
| `catseye` | Linux x86_64 (static) | ~6 MB |
| `catseye-crystal-extractor` | Linux aarch64 (static) | ~20 MB |
| `catseye-crystal-extractor` | Linux x86_64 (static) | ~20 MB |

### Distribution Layout

```
catseye-1.0.0-linux-aarch64.tar.gz
├── bin/
│   ├── catseye                       # Main binary
│   └── catseye-crystal-extractor     # Crystal extractor
├── rules/                            # KDL rule files
│   ├── ssrf.kdl
│   ├── command_injection.kdl
│   └── ...
├── README.md
└── LICENSE
```

---

## R2: CI Pipeline — Build + Test on PR

### Current State

The existing `.github/workflows/` only runs a self-scan on push. No build verification or test suite in CI.

### Target State

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@main
      - name: Build
        run: nix develop --command just build-ocaml
      - name: Upload binary
        uses: actions/upload-artifact@v4
        with:
          name: catseye-binary
          path: bin/catseye-ocaml

  test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@main
      - name: Run tests
        run: nix develop --command just test

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@main
      - name: Format check
        run: nix develop --command just lint

  scan-self:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@main
      - name: Build
        run: nix develop --command just build-ocaml
      - name: Self-scan
        run: nix develop --command "just scan-sarif ."
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: planning/catseye-results.sarif
          category: catseye
```

### CI Jobs

| Job | Trigger | Purpose |
|-----|---------|---------|
| `build` | Every push/PR | Verify `dune build` succeeds |
| `test` | Every push/PR | Run `dune test` + E2E validation |
| `lint` | Every push/PR | `dune build @fmt` check |
| `scan-self` | Every push/PR | Catseye scans itself, uploads SARIF |

---

## R3: Multi-Architecture Builds

### Targets

| Architecture | Runner | Priority |
|-------------|--------|----------|
| `aarch64-linux` | `ubuntu-24.04-arm` (or self-hosted) | Primary (current dev platform) |
| `x86_64-linux` | `ubuntu-latest` | Required — most CI/CD runners |
| `aarch64-macos` | `macos-latest` (M-series) | Stretch — needs macOS Nix |
| `x86_64-macos` | `macos-13` | Stretch — Intel macOS |

### Implementation

Use a matrix build in GitHub Actions:

```yaml
strategy:
  matrix:
    include:
      - runner: ubuntu-latest
        arch: x86_64-linux
      - runner: ubuntu-24.04-arm
        arch: aarch64-linux
```

**Note:** macOS builds require testing tree-sitter grammar availability in the Nix macOS sandbox. This is a stretch goal — ship Linux first.

---

## R4: opam Package Publication

### Current State

`dune-project` already has `(generate_opam_files true)`. Running `dune build` generates `.opam` files.

### Steps

1. **Generate opam files:**
   ```bash
   dune build  # generates catseye.opam
   ```

2. **Validate opam files:**
   ```bash
   opam lint catseye.opam
   ```

3. **Publish to opam repository:**
   ```bash
   # Fork github.com/ocaml/opam-repository
   # Add packages/catseye/catseye.1.0.0/opam
   # Submit PR
   ```

### opam File Requirements

The opam file must declare:
- All dependencies with version bounds
- Available on `linux` only (initially)
- `bin` field pointing to the compiled binary
- `doc` field pointing to the README

### External Dependency: tree-sitter

The Gleam extractor shells out to `tree-sitter` at runtime. This means `tree-sitter` + `tree-sitter-gleam` must be available at scan time. Options:

| Option | Pros | Cons |
|--------|------|------|
| **Shell out to tree-sitter** (current) | Simple, works | Requires tree-sitter in PATH |
| **Bundle tree-sitter as a library** | No external deps | Complex OCaml-C binding |
| **Make Gleam extraction optional** | Clean separation | Gleam users must install tree-sitter |

**Decision:** Keep tree-sitter as an external dependency. Document it clearly. The `justfile` and Nix shell handle this automatically. opam can declare `conf-tree-sitter` as a dependency.

---

## R5: Version Stamping

### Problem

Version is hardcoded in `engine.ml`:

```ocaml
let version = "0.3.0"
```

This must be updated manually for every release and is not visible in the binary metadata.

### Solution

Use Dune's `version` field from `dune-project` and embed it at build time:

```lisp
;; dune-project
(lang dune 3.17)
(name catseye)
(version 1.0.0)    ;; ← single source of truth
```

```ocaml
(* engine.ml *)
let version = Version.version  (* reads from dune-project at build time *)
```

Dune provides `(version)` via the `Version` module when `(name ...)` and `(version ...)` are in `dune-project`.

### CLI Version Flag

```ocaml
(* args.ml *)
| ("--version" | "-v") :: _ ->
  Printf.printf "Catseye v%s\n" Catseye_engine.Engine.version;
  exit 0
```

### Binary Metadata

```bash
# Embed version string in the ELF binary
chrpath --set-rpath '' bin/catseye 2>/dev/null
```

Or use Dune's `(-ldopt ...)` to embed a `.note` section.

---

## R6: Integration Test Suite

### Current State

Tests are run via `just test` which:
1. Runs `dune test` (unit tests)
2. Runs E2E: scans `test/samples/`, checks finding count
3. Runs safe-sample test: verifies zero findings

### Target State

Formalize this in `dune` test stanzas:

```lisp
;; test/dune
(test
 (name test_gleam)
 (libraries catseye.engine alcotest))

(test
 (name test_rules)
 (libraries catseye.rules catseye.engine alcotest))

(test
 (name test_e2e)
 (libraries catseye.cli alcotest)
 (action
  (run %{test} --vivid)))
```

### Test Categories

| Category | What | Where |
|----------|------|-------|
| **Unit** | Individual engine functions (propagate, interproc, dag) | `test/test_*.ml` via `dune test` |
| **E2E** | Full scan pipeline on test corpus | `just test` |
| **Differential** | OCaml engine vs. legacy results | `planning/ocaml-rewrite/differential/` |
| **Performance** | Scan time benchmarks | New: `test/bench.ml` |
| **Rule coverage** | Each rule fires on at least one test file | Implicit in E2E |

### Performance Benchmark

```ocaml
(* test/bench.ml *)
let () =
  let targets = [
    ("test/samples", 10);
    ("test/samples/safe.cr", 1);
  ] in
  List.iter (fun (path, expected_files) ->
    let t0 = Unix.gettimeofday () in
    (* run scan *)
    let t1 = Unix.gettimeofday () in
    Printf.printf "  %-40s %.3fs\n" path (t1 -. t0);
    assert (t1 -. t0 < 2.0)  (* budget: 2s for test corpus *)
  ) targets
```

---

## R7: Release Automation

### GitHub Release Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  release:
    strategy:
      matrix:
        include:
          - runner: ubuntu-latest
            arch: x86_64-linux
          - runner: ubuntu-24.04-arm
            arch: aarch64-linux
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4
      - uses: DeterminateSystems/nix-installer-action@main

      - name: Build
        run: |
          nix develop --command bash -c '
            just build-ocaml-release
            crystal build src/extractor/extractor.cr \
              -o bin/catseye-crystal-extractor --release --static
          '

      - name: Package
        run: |
          mkdir -p dist/bin dist/rules
          cp bin/catseye-ocaml dist/bin/catseye
          cp bin/catseye-crystal-extractor dist/bin/
          cp src/ocaml/rules/*.kdl dist/rules/
          cp README.md LICENSE dist/
          tar -czf catseye-${{ matrix.arch }}.tar.gz -C dist .

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: catseye-${{ matrix.arch }}
          path: catseye-${{ matrix.arch }}.tar.gz

  publish:
    needs: release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            catseye-x86_64-linux/catseye-x86_64-linux.tar.gz
            catseye-aarch64-linux/catseye-aarch64-linux.tar.gz
          generate_release_notes: true
```

### Release Checklist (Manual)

- [ ] Update version in `dune-project`
- [ ] Update version in `engine.ml` (or verify Dune auto-injects)
- [ ] Update `README.md` version references
- [ ] Update `CHANGELOG.md` (new file)
- [ ] Run full test suite: `just test`
- [ ] Scan real-world targets for regressions
- [ ] Tag: `git tag v1.0.0`
- [ ] Push tag: `git push origin v1.0.0`
- [ ] Verify GitHub Actions release workflow
- [ ] Download binaries, test on clean VM
- [ ] Publish to opam repository (if ready)

---

## R8: User Documentation

### What to Write

| Document | Purpose | Location |
|----------|---------|----------|
| **README.md** rewrite | User landing page, concise, install-first | Root |
| **CHANGELOG.md** | Version history, breaking changes | Root (new) |
| **Rule Authoring Guide** | How to write KDL rules | `docs/rules.md` (new) |
| **Configuration Guide** | Full `.catseye.toml` reference | `docs/configuration.md` (new) |
| **Integration Guide** | GitHub Actions, GitLab CI, pre-commit | `docs/integrations.md` (new) |
| **Architecture** | For contributors (condensed TDD) | `docs/architecture.md` (new) |

### README.md Restructure

The current README is thorough but developer-focused. Restructure for users:

```
1. One-line description + logo
2. Install (3 methods: binary, nix, opam)
3. Quick Start (3 commands to scan a project)
4. What It Detects (rule table)
5. Output Formats (terminal screenshot, SARIF, JSON)
6. Configuration (.catseye.toml example)
7. Development (link to CONTRIBUTING.md or docs/)
```

### Rule Authoring Guide (`docs/rules.md`)

```
1. Rule anatomy (sinks, sources, conditions, message)
2. KDL syntax reference
3. Taint-based vs pattern-based rules
4. Sanitizer definitions
5. Language filtering
6. Full example: creating a new rule
7. Testing rules
```

---

## R9: Nix Flake Package

### Current State

The Flake only provides `devShells`. No installable package.

### Target State

```nix
# flake.nix — add packages output

packages.${system} = {
  default = self.packages.${system}.catseye;

  catseye = pkgs.stdenv.mkDerivation {
    pname = "catseye";
    version = "1.0.0";
    src = self;
    # ... (full build derivation from R1)
  };
};
```

Users can then:

```bash
# Run directly
nix run github:kritoke/catseye -- /path/to/project

# Install
nix profile install github:kritoke/catseye
```

### nixpkgs Submission (Stretch)

Submit to `nixpkgs` as `pkgs.catseye`:

```nix
# packages/catseye/default.nix (in nixpkgs)
{ lib, ocamlPackages, crystal, tree-sitter, ... }:

ocamlPackages.buildDunePackage rec {
  pname = "catseye";
  version = "1.0.0";
  src = fetchFromGitHub { ... };
  buildInputs = with ocamlPackages; [ yojson toml kdl cmdliner ... ];
}
```

This is a stretch goal — requires nixpkgs review process.

---

## Implementation Order

```
R5 (version stamping)      ← Quick win, needed for everything
 │
 R6 (integration tests)    ← Must exist before release automation
 │
 R2 (CI pipeline)          ← Protects main branch
 │
 R1 (static binary)        ← Needed for distribution
 │
 R7 (release automation)   ← Depends on R1 + R2
 │
 R8 (documentation)        ← Can parallel with R1-R7
 │
 R9 (Nix package)          ← Depends on R1
 │
 R3 (multi-arch)           ← Stretch, after Linux works
 │
 R4 (opam)                 ← Last, requires stable API
```

---

## Exit Criteria

- [ ] `catseye` binary runs on a clean Ubuntu VM with no Nix installed
- [ ] `catseye --version` reports correct version from `dune-project`
- [ ] CI runs on every PR: build, test, lint, self-scan
- [ ] Tagged release creates GitHub Release with static binaries
- [ ] `nix run github:kritoke/catseye -- /path/to/project` works
- [ ] README is user-focused with install instructions
- [ ] Rule authoring guide exists with examples
- [ ] `CHANGELOG.md` exists with v1.0.0 entry
- [ ] All prior phases (6–9) are complete before tagging v1.0.0

---

## v1.0.0 Release Blockers

These must all be resolved before the release tag:

| Blocker | Phase | Description |
|---------|-------|-------------|
| Cross-file variable bleed | Phase 6 (F1) | False positives from shared taint namespace |
| Message truncation | Phase 6 (F2) | Broken finding output |
| Claws module | Phase 7 | Major advertised feature |
| Persistent cache | Phase 8 (P1) | Incremental scanning |
| Cross-file taint | Phase 9 | Significant analysis gap |

Items that are **NOT blockers** for v1.0.0:
- Multi-arch builds (ship aarch64-linux first)
- opam publication (can follow in v1.0.1)
- macOS support
- Ameba hook (optional Crystal feature)
- Svelte extractor (future language)
