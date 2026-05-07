# Catseye — justfile for build & dev tasks
# Run with: just <task>

set dotenv-load := false

# Default: build everything
default: build

# Build the Gleam engine
build-engine:
    cd src/engine && gleam build

# Build the Nim CLI
build-cli:
    nim c --out:bin/catseye src/cli/catseye.nim

# Build all components
build: build-engine
    @echo "✓ Engine built"

# Run the full pipeline on the test samples
test: build
    @echo "=== Vulnerable sample ==="
    @NODES=$$(CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- test/samples/vulnerable.cr 2>/dev/null) && \
    echo "$$NODES" | erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye:main(), erlang:halt()' 2>/dev/null | python3 -m json.tool
    @echo ""
    @echo "=== Safe sample (should be empty) ==="
    @NODES=$$(CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- test/samples/safe.cr 2>/dev/null) && \
    echo "$$NODES" | erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye:main(), erlang:halt()' 2>/dev/null

# Run just the Crystal extractor on a file
extract file:
    CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- {{file}}

# Run the engine on JSON from a file
analyze file:
    cat {{file}} | erl -noshell \
        -pa src/engine/build/dev/erlang/catseye_engine/ebin \
        -pa src/engine/build/dev/erlang/gleam_stdlib/ebin \
        -eval 'catseye:main(), erlang:halt()'

# Clean all build artifacts
clean:
    rm -rf src/engine/build
    rm -f bin/catseye

# Run the full Catseye CLI on a directory
scan dir:
    nim c -r --out:bin/catseye src/cli/catseye.nim -- {{dir}}
