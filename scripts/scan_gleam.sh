#!/usr/bin/env bash
## Catseye Scan — Gleam files
## Usage: scripts/scan_gleam.sh <directory>
## Run from project root inside nix develop.

set -euo pipefail

DIR="${1:-.}"
ENGINE_EBIN="src/engine/build/dev/erlang/catseye_engine/ebin"
STDLIB_EBIN="src/engine/build/dev/erlang/gleam_stdlib/ebin"
EXTRACTOR="bin/gleam_extractor"
TMPFILE=$(mktemp /tmp/catseye-XXXXXX.json)
trap "rm -f $TMPFILE" EXIT

# Build if needed
[ ! -f "$EXTRACTOR" ] && nim c --out:bin/gleam_extractor src/extractor/gleam_extractor.nim 2>/dev/null
[ ! -d "$ENGINE_EBIN" ] && (cd src/engine && gleam build 2>/dev/null)

echo ""
echo "╔══════════════════════════════════════╗"
echo "║          🔮 Catseye v0.1.0           ║"
echo "╚══════════════════════════════════════╝"

# Collect files
FILES=$(find "$DIR" -name '*.gleam' -not -path '*/build/*' -not -path '*/.git/*' -not -path '*/node_modules/*' | sort)
FILE_COUNT=$(echo "$FILES" | grep -c . || true)

echo "  Target:   $DIR"
echo "  Files:    $FILE_COUNT Gleam source(s)"
echo "  Engine:   Gleam/BEAM"
echo ""

if [ "$FILE_COUNT" -eq 0 ]; then
  echo "No .gleam files found."
  exit 0
fi

# Aggregate nodes using python for safe JSON merge
python3 -c "import sys,json; json.dump([],open('$TMPFILE','w'))"

NODE_COUNT=0
for f in $FILES; do
  echo "  → Extracting: $f"
  NODES=$("$EXTRACTOR" "$f" 2>/dev/null) || continue
  python3 -c "
import json, sys
new = json.loads('''$NODES'''.strip() or '[]')
with open('$TMPFILE') as f: existing = json.load(f)
existing.extend(new)
with open('$TMPFILE','w') as f: json.dump(existing, f)
" 2>/dev/null || true
  NC=$(echo "$NODES" | python3 -c "import sys,json; print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo 0)
  NODE_COUNT=$((NODE_COUNT + NC))
done

echo ""
echo "  → Running analysis engine ($NODE_COUNT nodes)..."
echo ""

# Send to engine
cat "$TMPFILE" | erl -noshell \
  -pa "$ENGINE_EBIN" \
  -pa "$STDLIB_EBIN" \
  -eval 'catseye:main(), erlang:halt()' 2>/dev/null

echo ""
echo "─────────────────────────────────────────"
