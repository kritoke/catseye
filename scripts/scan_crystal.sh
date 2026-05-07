#!/usr/bin/env bash
## Catseye Scan — Crystal files
## Usage: scripts/scan_crystal.sh <directory>
## Run from project root inside nix develop.

set -euo pipefail

DIR="${1:-.}"
ENGINE_EBIN="src/engine/build/dev/erlang/catseye_engine/ebin"
STDLIB_EBIN="src/engine/build/dev/erlang/gleam_stdlib/ebin"
TMPFILE=$(mktemp /tmp/catseye-crystal-XXXXXX.json)
trap "rm -f $TMPFILE" EXIT

# Build engine if needed
[ ! -d "$ENGINE_EBIN" ] && (cd src/engine && gleam build 2>/dev/null)

echo ""
echo "╔══════════════════════════════════════╗"
echo "║          🔮 Catseye v0.1.0           ║"
echo "║          Crystal Scanner             ║"
echo "╚══════════════════════════════════════╝"

# Collect files
FILES=$(find "$DIR" -name '*.cr' -not -path '*/lib/*' -not -path '*/.git/*' | sort)
FILE_COUNT=$(echo "$FILES" | grep -c . || true)

echo "  Target:   $DIR"
echo "  Files:    $FILE_COUNT Crystal source(s)"
echo "  Engine:   Gleam/BEAM"
echo ""

if [ "$FILE_COUNT" -eq 0 ]; then
  echo "No .cr files found."
  exit 0
fi

# Aggregate nodes using python for safe JSON merge
python3 -c "import json; json.dump([], open('$TMPFILE','w'))"

NODE_COUNT=0
SKIPPED=0
for f in $FILES; do
  NODES=$(CRYSTAL_HAS_WRAPPER=1 crystal run src/extractor/extractor.cr -- "$f" 2>/dev/null) || {
    SKIPPED=$((SKIPPED + 1))
    echo "  ⚠ Skipped (parse error): $f"
    continue
  }
  NC=$(echo "$NODES" | python3 -c "import sys,json; print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo 0)
  if [ "$NC" -gt 0 ]; then
    echo "  → $f ($NC nodes)"
    python3 -c "
import json
with open('$TMPFILE') as f: existing = json.load(f)
new = json.loads('''$(echo "$NODES" | head -c 100000)'''.strip() or '[]')
existing.extend(new)
with open('$TMPFILE','w') as f: json.dump(existing, f)
" 2>/dev/null || true
    NODE_COUNT=$((NODE_COUNT + NC))
  fi
done

echo ""
echo "  Total nodes: $NODE_COUNT"
if [ "$SKIPPED" -gt 0 ]; then
  echo "  Skipped:     $SKIPPED file(s)"
fi
echo ""
echo "  → Running analysis engine..."
echo ""

# Send to engine
RESULT=$(cat "$TMPFILE" | erl -noshell \
  -pa "$ENGINE_EBIN" \
  -pa "$STDLIB_EBIN" \
  -eval 'catseye:main(), erlang:halt()' 2>/dev/null)

echo "$RESULT" | python3 -c "
import sys, json
raw = sys.stdin.read().strip()
if not raw:
    print('  (no output from engine)')
    sys.exit(0)
findings = json.loads(raw)
if not findings:
    print('  ✨ No issues found.')
else:
    for f in findings:
        sev = f['severity']
        rule = f['rule']
        color = '\033[31m' if sev in ['Critical','High'] else '\033[33m'
        print(f'  {color}[{rule}] {sev}\033[0m \033[36m{f[\"file\"]}:{f[\"line\"]}\033[0m')
        print(f'    \033[2m{f[\"message\"][:140]}\033[0m')
        print()
    print(f'  \033[1mFound {len(findings)} issue(s).\033[0m')
"
echo ""
echo "─────────────────────────────────────────"
