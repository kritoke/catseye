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
    @echo "  Compiling Crystal extractors..."
    crystal build src/extractor/extractor.cr -o bin/catseye-crystal-extractor --release 2>/dev/null || true
    crystal build src/extractor/hierarchical_extractor.cr -o bin/catseye-hierarchical-extractor --release 2>/dev/null || true
    @echo "  Generating embedded rules (OCaml)..."
    cd src/ocaml && dune exec -- tools/generate_rules/main.exe rules lib/catseye_rules/default_rules.ml
    @echo "  Compiling OCaml..."
    cd src/ocaml && dune build && cp -f _build/default/bin/main.exe /workspaces/catseye/bin/catseye-ocaml
    cp -f src/ocaml/_build/default/tools/feedback/feedback.exe /workspaces/catseye/bin/catseye-feedback
    @echo "  Building Elixir escript..."
    cd /workspaces/catseye/scripts/elixir-extractor && MIX_ENV=prod mix escript.build 2>/dev/null && cp -f catseye_extractor /workspaces/catseye/bin/ || true
    @echo "✓ Built → bin/"

nix-build:
    nix develop --command bash -c "just build"

build-release:
    @mkdir -p bin
    crystal build src/extractor/extractor.cr -o bin/catseye-crystal-extractor --release 2>/dev/null || echo "  ⚠ Crystal not found"
    crystal build src/extractor/hierarchical_extractor.cr -o bin/catseye-hierarchical-extractor --release 2>/dev/null || true
    cd src/ocaml && dune exec -- tools/generate_rules/main.exe rules lib/catseye_rules/default_rules.ml
    @echo "  Compiling OCaml (release)..."
    cd src/ocaml && dune build --profile release && cp -f _build/default/bin/main.exe /workspaces/catseye/bin/catseye-ocaml
    @echo "  Building Elixir escript..."
    cd /workspaces/catseye/scripts/elixir-extractor && MIX_ENV=prod mix escript.build 2>/dev/null && cp -f catseye_extractor /workspaces/catseye/bin/ || true
    @echo "✓ Built (release) → bin/"

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
    @python3 -c "import json,sys; data=open('/tmp/catseye-test-out.json').read(); idx=data.find('{'); d=json.loads(data[idx:]); c=d['findings_count']; print(f'  Findings: {c} (expect >= 3)'); sys.exit(1 if c<3 else 0)"
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

# ── Feedback (Facet Pi) ──────────────────────────────────────────────

# Default feedback DB location
FACET_DB := "$HOME/.facet-pi/feedback.db"

# Show feedback summary (counts by type)
feedback db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" summary

# Show all scan results
feedback-scans db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" scans

# Show user-flagged false positives
feedback-fp db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" fp

# Show missed issues (things Catseye didn't catch)
feedback-missed db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" missed

# Show new findings manually reported by users
feedback-new db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" new

# Export all feedback as JSON (for AI consumption)
feedback-json db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" json

# Export feedback filtered by type as JSON
feedback-type type db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" json {{type}}

# Import catseye scan results into feedback DB (from file or stdin)
# Usage: just feedback-import results.json
#    or: catseye scan --format json /path | just feedback-import
feedback-import db=FACET_DB *args:
    @./bin/catseye-feedback -d "{{db}}" import {{args}}

# Scan and import in one step
feedback-scan dir db=FACET_DB:
    @./bin/catseye-ocaml --rules src/ocaml/rules --format json {{dir}} 2>/dev/null | ./bin/catseye-feedback -d "{{db}}" import

# ── Utilities ─────────────────────────────────────────────────────────

# Run Crystal extractor on a single file (debug)
extract file:
    CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- {{file}}

clean:
    rm -rf src/ocaml/_build bin/
    @echo "✓ Cleaned (run 'just build-extractors' to rebuild Crystal extractors)"

# Install to PREFIX (default ~/.local). Use $HOME not ~ for home dir.
# Usage: just install /usr/local  OR  just install "$HOME/.local"
install prefix="$HOME/.local": build
    @echo "Installing to {{prefix}} ..."
    @install -d {{prefix}}/bin
    @install -m 755 bin/catseye-ocaml {{prefix}}/bin/catseye-ocaml
    @install -m 755 bin/catseye-ocaml {{prefix}}/bin/catseye
    @install -m 755 bin/catseye_extractor {{prefix}}/bin/catseye-extractor 2>/dev/null || true
    @install -m 755 bin/catseye-feedback {{prefix}}/bin/catseye-feedback 2>/dev/null || true
    @install -d {{prefix}}/lib/catseye/rules
    @install -m 644 src/ocaml/rules/*.kdl {{prefix}}/lib/catseye/rules/
    @install -d {{prefix}}/lib/catseye/extractor
    @install -m 755 bin/catseye-crystal-extractor {{prefix}}/lib/catseye/extractor/catseye-crystal-extractor
    @install -m 755 bin/catseye-hierarchical-extractor {{prefix}}/lib/catseye/extractor/catseye-hierarchical-extractor 2>/dev/null || true
    @install -d {{prefix}}/lib/catseye/elixir-extractor
    @install -m 755 bin/catseye_extractor {{prefix}}/lib/catseye/elixir-extractor/catseye_extractor 2>/dev/null || true
    @echo "✓ Installed to {{prefix}}"
    @if ! echo ":$$PATH:" | grep -q ":$$HOME/.local/bin:"; then \
        echo "Hint: Add ~/.local/bin to your PATH"; \
    fi

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

uninstall prefix="$HOME/.local":
    @echo "Uninstalling from {{prefix}} ..."
    @rm -f {{prefix}}/bin/catseye-ocaml {{prefix}}/bin/catseye-extractor
    @rm -rf {{prefix}}/lib/catseye
    @echo "✓ Uninstalled from {{prefix}}"

# Generate AI-ready report from feedback (for rule improvement)
feedback-report db=FACET_DB:
    @./bin/catseye-feedback -d "{{db}}" json

# Feed false positives + missed issues into an improvement prompt
# Usage: just feedback-ai | pi --mode rpc prompt
feedback-ai db=FACET_DB:
    @echo "## Catseye Feedback Report for Rule Improvement"
    @echo ""
    @echo "### False Positives (rules that are too noisy)"
    @./bin/catseye-feedback -d "{{db}}" json false_positive
    @echo ""
    @echo "### Missed Issues (things Catseye did not detect)"
    @./bin/catseye-feedback -d "{{db}}" json missed_issue
    @echo ""
    @echo "### New Findings (user-reported security issues Catseye should detect)"
    @./bin/catseye-feedback -d "{{db}}" json new_finding
    @echo ""
    @echo "### Current Rule Set"
    @ls rules/*.kdl 2>/dev/null || echo "No rules directory found"
    @echo ""
    @echo "### Instructions"
    @echo "Based on the false positives above, propose rule refinements to reduce noise."
    @echo "Based on the missed issues and new findings, propose new rules or rule modifications."
    @echo "Output concrete KDL rule changes with explanations."

list:
    @just --list
