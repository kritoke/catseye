# Catseye — build & dev tasks
#
# Commands come in pairs: plain (needs tools installed) and _nix (uses nix develop).
# Use plain commands if you have OCaml/Crystal/tree-sitter already.
# Use nix-prefixed commands if you want nix to provide the toolchain.

# ── Aliases ───────────────────────────────────────────────────────────

alias b := build
alias t := test
alias s := scan

# ── Build ─────────────────────────────────────────────────────────────

build:
    @mkdir -p bin
    @if [ ! -f bin/catseye-crystal-extractor ]; then \
        echo "  Compiling Crystal extractors (first build)..."; \
        crystal build src/extractor/extractor.cr -o bin/catseye-crystal-extractor --release 2>/dev/null || true; \
    fi
    @if [ ! -f bin/catseye-hierarchical-extractor ]; then \
        crystal build src/extractor/hierarchical_extractor.cr -o bin/catseye-hierarchical-extractor --release 2>/dev/null || true; \
    fi
    cd src/ocaml && dune build
    cp -f src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ Built → bin/catseye-ocaml"

nix-build:
    nix develop --command bash -c "just build"

build-release:
    @mkdir -p bin
    crystal build src/extractor/extractor.cr -o bin/catseye-crystal-extractor --release 2>/dev/null || echo "  ⚠ Crystal not found, extractor will use crystal run (slow)"
    crystal build src/extractor/hierarchical_extractor.cr -o bin/catseye-hierarchical-extractor --release 2>/dev/null || true
    cd src/ocaml && dune build --profile release
    cp -f src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ Built (release) → bin/catseye-ocaml"

build-extractors:
    @mkdir -p bin
    crystal build src/extractor/extractor.cr -o bin/catseye-crystal-extractor --release
    crystal build src/extractor/hierarchical_extractor.cr -o bin/catseye-hierarchical-extractor --release
    @echo "✓ Built extractors → bin/catseye-crystal-extractor, bin/catseye-hierarchical-extractor"

# ── Test ──────────────────────────────────────────────────────────────

test: build
    @echo "=== Unit tests ==="
    cd src/ocaml && dune test
    @echo ""
    @echo "=== E2E: Vulnerable samples ==="
    @./bin/catseye-ocaml --rules src/ocaml/rules --format json test/samples/ > /tmp/catseye-test-out.json 2>/dev/null || true
    @python3 -c "import json,sys; data=open('/tmp/catseye-test-out.json').read(); idx=data.find('{'); d=json.loads(data[idx:]); c=d['findings_count']; print(f'  Findings: {c} (expect >= 10)'); sys.exit(1 if c<10 else 0)"
    @echo "  ✓ Finding count OK"
    @echo ""
    @echo "=== E2E: Safe samples ==="
    @mkdir -p /tmp/catseye-safe-test && cp test/samples/safe.cr /tmp/catseye-safe-test/
    @./bin/catseye-ocaml --rules src/ocaml/rules --format json /tmp/catseye-safe-test/ > /tmp/catseye-safe-out.json 2>/dev/null || true
    @python3 -c "import json,sys; data=open('/tmp/catseye-safe-out.json').read(); idx=data.find('{'); d=json.loads(data[idx:]); c=d['findings_count']; print(f'  Findings: {c} (expect 0)'); sys.exit(1 if c!=0 else 0)"
    @echo "  ✓ Safe samples clean"
    @echo ""
    @echo "=== E2E: Code smell detection ==="
    @./bin/catseye-ocaml --rules src/ocaml/rules --format json --claws test/samples/smell_samples/ > /tmp/catseye-claws-out.json 2>/dev/null || true
    @python3 -c "import json,sys; data=open('/tmp/catseye-claws-out.json').read(); idx=data.find('{'); d=json.loads(data[idx:]); c=d['findings_count']; rules=set(f['rule'] for f in d['findings']); expected={'LongParameterList','GodObject','DeepNesting'}; missing=expected-rules; print(f'  Findings: {c} (expect >= 3)'); print(f'  Rules: {sorted(rules)}'); sys.exit(1 if c<3 or missing else 0)"
    @echo "  ✓ Code smell detection OK"
    @echo ""
    @echo "✓ All tests passed"

nix-test:
    nix develop --command just test

# ── Scan ──────────────────────────────────────────────────────────────

# Scan — terminal output
scan dir: build
    ./bin/catseye-ocaml --rules src/ocaml/rules {{dir}} || [ $$? -le 1 ]

nix-scan dir:
    nix develop --command just scan {{dir}}

# Scan with all checks
scan-full dir: build
    ./bin/catseye-ocaml --rules src/ocaml/rules --predator-vision --crows-nest --claws --ai-lint {{dir}} || [ $$? -le 1 ]

# JSON output
scan-json dir: build
    ./bin/catseye-ocaml --rules src/ocaml/rules --format json {{dir}} || [ $$? -le 1 ]

# Code smells only
scan-claws dir: build
    ./bin/catseye-ocaml --rules src/ocaml/rules --claws {{dir}} || [ $$? -le 1 ]

# AI antipatterns only
scan-ai dir: build
    ./bin/catseye-ocaml --rules src/ocaml/rules --ai-lint {{dir}} || [ $$? -le 1 ]

# Generate all report formats to <dir>/planning/
scan-reports dir: build
    @mkdir -p {{dir}}/planning
    ./bin/catseye-ocaml --rules src/ocaml/rules --format json --claws -o {{dir}}/planning/catseye-scan-results.json {{dir}} || true
    ./bin/catseye-ocaml --rules src/ocaml/rules --format markdown --claws -o {{dir}}/planning/catseye-security-report.md {{dir}} || true
    ./bin/catseye-ocaml --rules src/ocaml/rules --format sarif --claws -o {{dir}}/planning/catseye-scan-results.sarif {{dir}} || true
    @echo "✓ Reports → {{dir}}/planning/"

# ── Format & Lint ─────────────────────────────────────────────────────

fmt:
    cd src/ocaml && dune fmt

lint:
    cd src/ocaml && dune build @fmt

# ── Utilities ─────────────────────────────────────────────────────────

# Run Crystal extractor on a single file (debug)
extract file:
    CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- {{file}}

clean:
    rm -rf src/ocaml/_build bin/
    @echo "✓ Cleaned (run 'just build-extractors' to rebuild Crystal extractors)"

# Install to PREFIX (default /usr/local)
# Install to PREFIX (default /usr/local). Use $HOME not ~ for home dir.
# Usage: just install /usr/local  OR  just install "$HOME/.local"
install prefix="/usr/local": build
    install -d {{prefix}}/bin
    install -m 755 bin/catseye-ocaml {{prefix}}/bin/catseye-ocaml
    install -d {{prefix}}/lib/catseye/rules
    install -m 644 src/ocaml/rules/*.kdl {{prefix}}/lib/catseye/rules/
    install -d {{prefix}}/lib/catseye/extractor
    install -m 755 bin/catseye-crystal-extractor {{prefix}}/lib/catseye/extractor/catseye-crystal-extractor
    @echo "✓ Installed to {{prefix}}"

# Install pi extension (project-local)
install-pi:
    @mkdir -p .pi/extensions/catseye-scan
    @cp extensions/pi-catseye-scan/index.ts .pi/extensions/catseye-scan/
    @echo "✓ Pi extension installed locally → .pi/extensions/catseye-scan/"

# Install pi extension globally
install-pi-global:
    @mkdir -p ~/.pi/agent/extensions/catseye-scan
    @cp extensions/pi-catseye-scan/index.ts ~/.pi/agent/extensions/catseye-scan/
    @echo "✓ Pi extension installed globally → ~/.pi/agent/extensions/catseye-scan/"

uninstall prefix="/usr/local":
    rm -f {{prefix}}/bin/catseye-ocaml
    rm -rf {{prefix}}/lib/catseye
    @echo "✓ Uninstalled from {{prefix}}"

list:
    @just --list
