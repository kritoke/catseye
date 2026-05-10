# Catseye — build & dev tasks
# Run: just <task>
#
# All OCaml/dune tasks are wrapped with nix develop so the
# toolchain (ocaml, dune, opam libs) is always available.

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

# ── Scan ──────────────────────────────────────────────────────────────

# Scan — terminal output
scan dir: build-ocaml
    ./bin/catseye-ocaml --rules src/ocaml/rules {{dir}}

# Scan with Hunter persona + Predator Vision + Crow's Nest
scan-hunter dir: build-ocaml
    ./bin/catseye-ocaml --rules src/ocaml/rules --predator-vision --crows-nest {{dir}}

# Scan — JSON to stdout
scan-json dir: build-ocaml
    ./bin/catseye-ocaml --rules src/ocaml/rules --format json {{dir}}

# Scan — JSON to file
scan-json-file dir: build-ocaml
    @mkdir -p {{dir}}/planning
    ./bin/catseye-ocaml --rules src/ocaml/rules --format json \
        -o {{dir}}/planning/catseye-scan-results.json {{dir}}
    @echo "✓ JSON → {{dir}}/planning/catseye-scan-results.json"

# Scan — SARIF to file
scan-sarif dir: build-ocaml
    @mkdir -p {{dir}}/planning
    ./bin/catseye-ocaml --rules src/ocaml/rules --format sarif \
        -o {{dir}}/planning/catseye-scan-results.sarif {{dir}}
    @echo "✓ SARIF → {{dir}}/planning/catseye-scan-results.sarif"

# Scan — Markdown to file
scan-md dir: build-ocaml
    @mkdir -p {{dir}}/planning
    ./bin/catseye-ocaml --rules src/ocaml/rules --format markdown \
        -o {{dir}}/planning/catseye-security-report.md {{dir}}
    @echo "✓ Markdown → {{dir}}/planning/catseye-security-report.md"

# Scan — all formats to planning/
scan-all dir: build-ocaml
    @mkdir -p {{dir}}/planning
    ./bin/catseye-ocaml --rules src/ocaml/rules --format json \
        -o {{dir}}/planning/catseye-scan-results.json {{dir}}
    ./bin/catseye-ocaml --rules src/ocaml/rules --format markdown \
        -o {{dir}}/planning/catseye-security-report.md {{dir}}
    ./bin/catseye-ocaml --rules src/ocaml/rules --format sarif \
        -o {{dir}}/planning/catseye-scan-results.sarif {{dir}}
    @echo "✓ All reports → {{dir}}/planning/"

# ── Test ───────────────────────────────────────────────────────────────

test: test-ocaml
    @echo ""
    @echo "=== E2E: Vulnerable samples ==="
    @./bin/catseye-ocaml --rules src/ocaml/rules --format=json test/samples/ > /tmp/catseye-test-out.json 2>/dev/null
    @python3 -c "import json,sys; d=json.load(open('/tmp/catseye-test-out.json')); c=d['findings_count']; print(f'  Findings: {c} (expect >= 10)'); sys.exit(1 if c<10 else 0)"
    @echo "  ✓ Finding count OK"
    @echo ""
    @echo "=== E2E: Safe samples ==="
    @mkdir -p /tmp/catseye-safe-test && cp test/samples/safe.cr /tmp/catseye-safe-test/
    @./bin/catseye-ocaml --rules src/ocaml/rules --format=json /tmp/catseye-safe-test > /tmp/catseye-safe-out.json 2>/dev/null
    @python3 -c "import json,sys; d=json.load(open('/tmp/catseye-safe-out.json')); c=d['findings_count']; print(f'  Findings: {c} (expect 0)'); sys.exit(1 if c!=0 else 0)"
    @echo "  ✓ Safe samples clean"
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
