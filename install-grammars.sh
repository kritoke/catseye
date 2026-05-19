#!/bin/bash
# Install tree-sitter grammars for Catseye
set -e

GRAMMAR_DIR="${CATSEYE_GRAMMAR_DIR:-$HOME/.local/share/catseye/grammars}"
mkdir -p "$GRAMMAR_DIR"

echo "Installing tree-sitter grammars..."
echo "Destination: $GRAMMAR_DIR"

# Install grammars via npm packages
# These packages contain pre-built .wasm parsers and .json schemas
for lang in javascript typescript rust python go; do
	echo "  Installing $lang..."
	TMP=$(mktemp -d)
	if npm pack "@tree-sitter-grammars/tree-sitter-$lang" --pack-destination "$TMP" 2>/dev/null; then
		PKG=$(ls "$TMP"/tree-sitter-$lang-*.tgz 2>/dev/null | head -1)
		if [ -n "$PKG" ]; then
			mkdir -p "$GRAMMAR_DIR/tree-sitter-$lang"
			tar -xzf "$PKG" -C "$GRAMMAR_DIR/tree-sitter-$lang" --strip-components=1 2>/dev/null || true
		fi
	fi
	rm -rf "$TMP"
done

# Also try the official tree-sitter packages
for lang in javascript typescript; do
	if [ ! -d "$GRAMMAR_DIR/tree-sitter-$lang" ]; then
		echo "  Installing $lang (official)..."
		TMP=$(mktemp -d)
		if npm pack "tree-sitter-$lang" --pack-destination "$TMP" 2>/dev/null; then
			PKG=$(ls "$TMP"/tree-sitter-$lang-*.tgz 2>/dev/null | head -1)
			if [ -n "$PKG" ]; then
				mkdir -p "$GRAMMAR_DIR/tree-sitter-$lang"
				tar -xzf "$PKG" -C "$GRAMMAR_DIR/tree-sitter-$lang" --strip-components=1 2>/dev/null || true
			fi
		fi
		rm -rf "$TMP"
	fi
done

echo ""
echo "✓ Grammar installation complete"
echo "  Location: $GRAMMAR_DIR"
echo "  Set CATSEYE_GRAMMAR_DIR to customize"
