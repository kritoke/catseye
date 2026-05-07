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

unit-test: build-engine
    @erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye@test_runner:main(), erlang:halt()'

test: build unit-test
    @echo ""
    @echo "=== Vulnerable sample ==="
    @./bin/catseye test/samples/ 2>&1 || true
    @echo ""
    @echo "=== Safe sample (expect 0 findings) ==="
    @mkdir -p /tmp/catseye-safe-test && cp test/samples/safe.cr /tmp/catseye-safe-test/ && ./bin/catseye /tmp/catseye-safe-test

# ── Lint (all languages) ──────────────────────────────────────────────

lint: lint-gleam lint-crystal lint-nim
    @echo "✓ All lints passed"

# Check Gleam formatting
lint-gleam:
    cd src/engine && gleam format --check src

# Check Crystal with ameba
lint-crystal:
    CRYSTAL_HAS_WRAPPER=1 ameba src/extractor/ test/samples/

# Check Nim with compiler checks
lint-nim:
    nim check src/cli/catseye.nim

# Auto-fix Gleam formatting
fmt-gleam:
    cd src/engine && gleam format src

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
