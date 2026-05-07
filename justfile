# Catseye — build & dev tasks
# Run: just <task>

# Build everything
default: build

# Build the Gleam engine
build-engine:
    cd src/engine && gleam build

# Build the Nim CLI
build-cli:
    nim c --out:bin/catseye src/cli/catseye.nim

# Build all components
build: build-engine build-cli
    @echo "✓ All components built"

# Run end-to-end test on sample files
test: build
    @echo "=== Vulnerable sample ==="
    @./bin/catseye test/samples/ --no-color || true
    @echo ""
    @echo "=== Safe sample (expect 0 findings) ==="
    @./bin/catseye test/samples/safe.cr --no-color

# Run just the Crystal extractor on a file
extract file:
    CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- {{file}}

# Run the Gleam engine on JSON from stdin or a file
analyze file:
    @cat {{file}} | erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye:main(), erlang:halt()'

# Scan a directory with the full CLI
scan dir: build
    ./bin/catseye {{dir}}

# Clean all build artifacts
clean:
    rm -rf src/engine/build bin/
    @echo "✓ Cleaned"
