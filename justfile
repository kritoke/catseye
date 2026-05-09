# Catseye — build & dev tasks
# Run: just <task>

# Build everything (legacy)
default: build

# Build OCaml version
ocaml: build-ocaml

# ── OCaml Build ──────────────────────────────────────────────────────

build-ocaml:
    cd src/ocaml && dune build
    cp src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ OCaml catseye built → bin/catseye-ocaml"

build-ocaml-release:
    cd src/ocaml && dune build --profile release
    cp src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ OCaml catseye built (release) → bin/catseye-ocaml"

test-ocaml: build-ocaml
    cd src/ocaml && dune test
    @echo "✓ OCaml tests passed"

lint-ocaml:
    cd src/ocaml && dune build @fmt

fmt-ocaml:
    cd src/ocaml && dune fmt

clean-ocaml:
    rm -rf src/ocaml/_build
    @echo "✓ OCaml build cleaned"

# Scan using the OCaml engine
scan-ocaml dir: build-ocaml
    ./bin/catseye-ocaml {{dir}}

scan-ocaml-json dir: build-ocaml
    ./bin/catseye-ocaml --format json {{dir}}

# ── Build ──────────────────────────────────────────────────────────────

build-engine:
    cd src/engine && gleam build

build-extractors: build-engine
    nim c --out:bin/gleam_extractor src/extractor/gleam_extractor.nim

build-cli:
    nim c --out:bin/catseye src/cli/catseye.nim

build: build-engine build-extractors build-cli
    @echo "✓ All components built"

# ── Scan (all languages) ───────────────────────────────────────────────

# Scan a directory for all supported languages
scan dir: build
    ./bin/catseye {{dir}}

# Scan with JSON output to file
scan-json dir: build
    ./bin/catseye --format json --output {{dir}}/planning/catseye-scan-results.json {{dir}}

# Scan with SARIF output to file
scan-sarif dir: build
    ./bin/catseye --format sarif --output {{dir}}/planning/catseye-scan-results.sarif {{dir}}

# Scan with Markdown report to file
scan-md dir: build
    ./bin/catseye --format markdown --output {{dir}}/planning/catseye-security-report.md {{dir}}

# Scan with all output formats to planning/
scan-all dir: build
    @mkdir -p {{dir}}/planning
    ./bin/catseye --format json --output {{dir}}/planning/catseye-scan-results.json {{dir}}
    ./bin/catseye --format markdown --output {{dir}}/planning/catseye-security-report.md {{dir}}
    ./bin/catseye --format sarif --output {{dir}}/planning/catseye-scan-results.sarif {{dir}}
    @echo "✓ All reports written to {{dir}}/planning/"

# ── Scan (Crystal only) ───────────────────────────────────────────────

# Scan only Crystal (.cr) files
scan-crystal dir: build
    ./bin/catseye --lang crystal {{dir}}

# Scan Crystal and save all reports to planning/
scan-crystal-all dir: build
    @mkdir -p {{dir}}/planning
    ./bin/catseye --format json --lang crystal --output {{dir}}/planning/catseye-scan-results.json {{dir}}
    ./bin/catseye --format markdown --lang crystal --output {{dir}}/planning/catseye-security-report.md {{dir}}
    @echo "✓ Crystal reports written to {{dir}}/planning/"

# ── Scan (Gleam only) ─────────────────────────────────────────────────

# Scan only Gleam (.gleam) files
scan-gleam dir: build
    ./bin/catseye --lang gleam {{dir}}

# ── Test ───────────────────────────────────────────────────────────────

# Run Gleam engine unit tests
unit-test: build-engine
    @erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye@test_runner:main(), erlang:halt()'

# Full E2E test pipeline
test: build unit-test
    @echo ""
    @echo "=== E2E: Vulnerable samples ==="
    @./bin/catseye --format=json test/samples/ > /tmp/catseye-test-out.json 2>/dev/null
    @python3 -c "import json,sys; d=json.load(open('/tmp/catseye-test-out.json')); c=d['findings_count']; print(f'  Findings: {c} (expect >= 10)'); sys.exit(1 if c<10 else 0)"
    @echo "  ✓ Finding count OK"
    @echo ""
    @echo "=== E2E: Safe samples ==="
    @mkdir -p /tmp/catseye-safe-test && cp test/samples/safe.cr test/samples/safe.gleam /tmp/catseye-safe-test/
    @./bin/catseye --format=json /tmp/catseye-safe-test > /tmp/catseye-safe-out.json 2>/dev/null
    @python3 -c "import json,sys; d=json.load(open('/tmp/catseye-safe-out.json')); c=d['findings_count']; print(f'  Findings: {c} (expect 0)'); sys.exit(1 if c!=0 else 0)"
    @echo "  ✓ Safe samples clean"
    @echo ""
    @echo "=== E2E: SARIF output ==="
    @./bin/catseye --format=sarif test/samples/ > /tmp/catseye-sarif-out.json 2>/dev/null
    @python3 -c "import json; d=json.load(open('/tmp/catseye-sarif-out.json')); assert d['version']=='2.1.0'; r=d['runs'][0]['results']; f=[x for x in r if 'codeFlows' in x]; print(f'  SARIF: {len(r)} results, {len(f)} with codeFlows')"
    @echo "  ✓ SARIF valid"
    @echo ""
    @echo "✓ All E2E tests passed"

# ── Lint (all languages) ──────────────────────────────────────────────

lint: lint-gleam lint-crystal lint-nim
    @echo "✓ All lints passed"

lint-gleam:
    cd src/engine && nix develop --command bash -c 'gleam format --check src'

lint-crystal:
    nix develop --command bash -c 'CRYSTAL_HAS_WRAPPER=1 ameba src/extractor/ test/samples/'

lint-nim:
    nix develop --command bash -c 'nim check src/cli/catseye.nim && nim check src/extractor/gleam_extractor.nim'

fmt-gleam:
    cd src/engine && nix develop --command bash -c 'gleam format src'

# ── Utilities ──────────────────────────────────────────────────────────

# Run Crystal extractor on a single file (debug)
extract file:
    CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- {{file}}

# Run Gleam extractor on a single file (debug)
extract-gleam file: build-extractors
    ./bin/gleam_extractor {{file}}

# Pipe JSON to the engine directly (debug)
analyze file:
    @cat {{file}} | erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye:main(), erlang:halt()'

# List all recipes
list:
    @just --list

clean: clean-ocaml
    rm -rf src/engine/build bin/
    @echo "✓ Cleaned"
