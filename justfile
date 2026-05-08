# Catseye — build & dev tasks
# Run: just <task>

# Build everything
default: build

# ── Build ──────────────────────────────────────────────────────────────

build-engine:
    cd src/engine && gleam build

build-cli:
    nim c --out:bin/catseye src/cli/catseye.nim

build: build-engine build-cli
    @echo "✓ All components built"

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

# Check Gleam formatting
lint-gleam:
    cd src/engine && nix develop --command bash -c 'gleam format --check src'

# Check Crystal with ameba
lint-crystal:
    nix develop --command bash -c 'CRYSTAL_HAS_WRAPPER=1 ameba src/extractor/ test/samples/'

# Check Nim with compiler checks
lint-nim:
    nix develop --command bash -c 'nim check src/cli/catseye.nim && nim check src/extractor/gleam_extractor.nim'

# Auto-fix Gleam formatting
fmt-gleam:
    cd src/engine && nix develop --command bash -c 'gleam format src'

# ── Utilities ──────────────────────────────────────────────────────────

extract file:
    CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- {{file}}

analyze file:
    @cat {{file}} | erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye:main(), erlang:halt()'

scan dir: build
    ./bin/catseye {{dir}}

clean:
    rm -rf src/engine/build bin/
    @echo "✓ Cleaned"
