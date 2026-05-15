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
    cd src/ocaml && dune build
    @mkdir -p bin
    cp -f src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ Built → bin/catseye-ocaml"

nix-build:
    nix develop --command bash -c "cd src/ocaml && dune build"
    @mkdir -p bin
    cp -f src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ Built → bin/catseye-ocaml"

build-release:
    cd src/ocaml && dune build --profile release
    @mkdir -p bin
    cp -f src/ocaml/_build/default/bin/main.exe bin/catseye-ocaml
    @echo "✓ Built (release) → bin/catseye-ocaml"

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
    @echo "✓ Cleaned"

# Install to PREFIX (default /usr/local)
install prefix="/usr/local": build
    install -d {{prefix}}/bin
    install -m 755 bin/catseye-ocaml {{prefix}}/bin/catseye-ocaml
    install -d {{prefix}}/lib/catseye/rules
    install -m 644 src/ocaml/rules/*.kdl {{prefix}}/lib/catseye/rules/
    install -d {{prefix}}/lib/catseye/extractor
    install -m 755 bin/catseye-crystal-extractor {{prefix}}/lib/catseye/extractor/catseye-crystal-extractor
    @echo "✓ Installed to {{prefix}}"

uninstall prefix="/usr/local":
    rm -f {{prefix}}/bin/catseye-ocaml
    rm -rf {{prefix}}/lib/catseye
    @echo "✓ Uninstalled from {{prefix}}"

list:
    @just --list
