#!/bin/bash
# Setup tree-sitter grammars for Catseye
# Run this once after installation

GRAMMAR_DIR="${CATSEYE_GRAMMAR_DIR:-$HOME/.local/share/catseye/grammars}"

echo "Setting up tree-sitter grammars in $GRAMMAR_DIR..."

mkdir -p "$GRAMMAR_DIR"

# Download grammar repo
if [ ! -d "$GRAMMAR_DIR/tree-sitter-grammars" ]; then
    echo "Downloading tree-sitter-grammars..."
    curl -sL https://github.com/tree-sitter/tree-sitter-grammars/archive/refs/heads/master.tar.gz | tar -xz -C "$GRAMMAR_DIR" --strip-components=1
fi

# Link grammars to expected locations
for lang in javascript typescript rust python go cpp c; do
    src="$GRAMMAR_DIR/tree-sitter-grammars/tree-sitter-$lang"
    if [ -d "$src" ]; then
        mkdir -p "$GRAMMAR_DIR/$lang"
        cp -r "$src/src" "$GRAMMAR_DIR/$lang/" 2>/dev/null || true
    fi
done

echo "✓ Grammars setup complete"
echo "Set CATSEYE_GRAMMAR_DIR to customize location"
