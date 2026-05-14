# Catseye — build & dev tasks
# Run: just <task>
#
# All OCaml/dune tasks and scan tasks are wrapped with nix develop
# so the full toolchain (ocaml, dune, tree-sitter) is always available.

# ── Constants ─────────────────────────────────────────────────────────

root := justfile_directory()

# ── Nix wrapper ───────────────────────────────────────────────────────

# Internal: run a command inside the nix dev shell
_nix cmd:
    nix develop --command bash -c "{{cmd}}"

# ── OCaml Engine ──────────────────────────────────────────────────────

ocaml: build-ocaml

build-ocaml:
    just _nix "cd src/ocaml && dune build"
    @mkdir -p bin
    cp -f src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ OCaml engine built → bin/catseye-ocaml"

build-ocaml-release:
    just _nix "cd src/ocaml && dune build --profile release"
    @mkdir -p bin
    cp -f src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ OCaml engine built (release) → bin/catseye-ocaml"

test-ocaml: build-ocaml
    just _nix "cd src/ocaml && dune test"
    @echo "✓ OCaml tests passed"

lint-ocaml:
    just _nix "cd src/ocaml && dune build @fmt"

fmt-ocaml:
    just _nix "cd src/ocaml && dune fmt"

clean-ocaml:
    rm -rf src/ocaml/_build
    @echo "✓ OCaml build cleaned"

# ── Internal scan helper ──────────────────────────────────────────────

# Run catseye-ocaml inside nix with the correct binary and rules paths
# Exit code 1 = findings found (not an error), 2+ = actual error
_do-scan dir flags:
    just _nix "cd {{root}} && ./bin/catseye-ocaml --rules src/ocaml/rules {{flags}} {{dir}} || [ $? -le 1 ]"

# ── Scan ──────────────────────────────────────────────────────────────

# Scan — terminal output
scan dir: build-ocaml
    just _do-scan {{dir}} ""

# Scan with all analysis passes
scan-all-features dir: build-ocaml
    just _do-scan {{dir}} "--predator-vision --crows-nest --claws"

# Scan — Claws code smell & DRY analysis
scan-claws dir: build-ocaml
    just _do-scan {{dir}} "--claws"

# Scan — JSON to stdout
scan-json dir: build-ocaml
    just _do-scan {{dir}} "--format json"

# Scan — JSON to file
scan-json-file dir: build-ocaml
    @mkdir -p {{dir}}/planning
    just _do-scan {{dir}} "--format json -o {{dir}}/planning/catseye-scan-results.json"
    @echo "✓ JSON → {{dir}}/planning/catseye-scan-results.json"

# Scan — SARIF to file
scan-sarif dir: build-ocaml
    @mkdir -p {{dir}}/planning
    just _do-scan {{dir}} "--format sarif -o {{dir}}/planning/catseye-scan-results.sarif"
    @echo "✓ SARIF → {{dir}}/planning/catseye-scan-results.sarif"

# Scan — Markdown to file
scan-md dir: build-ocaml
    @mkdir -p {{dir}}/planning
    just _do-scan {{dir}} "--format markdown -o {{dir}}/planning/catseye-security-report.md"
    @echo "✓ Markdown → {{dir}}/planning/catseye-security-report.md"

# Scan — all formats + Claws to planning/
scan-all dir: build-ocaml
    @mkdir -p {{dir}}/planning
    just _do-scan {{dir}} "--format json --claws -o {{dir}}/planning/catseye-scan-results.json"
    just _do-scan {{dir}} "--format markdown --claws -o {{dir}}/planning/catseye-security-report.md"
    just _do-scan {{dir}} "--format sarif --claws -o {{dir}}/planning/catseye-scan-results.sarif"
    @echo "✓ All reports → {{dir}}/planning/"

# ── Test ───────────────────────────────────────────────────────────────

test: test-ocaml
    @echo ""
    @echo "=== E2E: Vulnerable samples ==="
    @just _do-scan "test/samples/" "--format json" > /tmp/catseye-test-out.json 2>/dev/null
    @python3 -c "import json,sys; data=open('/tmp/catseye-test-out.json').read(); idx=data.find('{'); d=json.loads(data[idx:]); c=d['findings_count']; print(f'  Findings: {c} (expect >= 10)'); sys.exit(1 if c<10 else 0)"
    @echo "  ✓ Finding count OK"
    @echo ""
    @echo "=== E2E: Safe samples ==="
    @mkdir -p /tmp/catseye-safe-test && cp test/samples/safe.cr /tmp/catseye-safe-test/
    @just _do-scan "/tmp/catseye-safe-test/" "--format json" > /tmp/catseye-safe-out.json 2>/dev/null
    @python3 -c "import json,sys; data=open('/tmp/catseye-safe-out.json').read(); idx=data.find('{'); d=json.loads(data[idx:]); c=d['findings_count']; print(f'  Findings: {c} (expect 0)'); sys.exit(1 if c!=0 else 0)"
    @echo "  ✓ Safe samples clean"
    @echo ""
    @echo "=== E2E: Claws smell detection ==="
    @just _do-scan "test/samples/smell_samples/" "--format json --claws" > /tmp/catseye-claws-out.json 2>/dev/null
    @python3 -c "import json,sys; data=open('/tmp/catseye-claws-out.json').read(); idx=data.find('{'); d=json.loads(data[idx:]); c=d['findings_count']; rules=set(f['rule'] for f in d['findings']); expected={'LongParameterList','GodObject','DRYViolation'}; missing=expected-rules; print(f'  Findings: {c} (expect >= 3)'); print(f'  Smell rules: {sorted(rules)}'); sys.exit(1 if c<3 or missing else 0)"
    @echo "  ✓ Claws smell detection OK"
    @echo ""
    @echo "✓ All E2E tests passed"

# ── Lint ───────────────────────────────────────────────────────────────

lint: lint-ocaml
    @echo "✓ All lints passed"

# ── Utilities ──────────────────────────────────────────────────────────

# Run Crystal extractor on a single file (debug)
extract file:
    CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- {{file}}

# List all recipes
list:
    @just --list

clean: clean-ocaml
    rm -rf bin/
    @echo "✓ Cleaned"
