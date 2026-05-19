#!/bin/bash
# Install tree-sitter grammars for Catseye
set -e

# Grammars can be installed to ~/.tree-sitter/ (standard tree-sitter location)
# or to a custom directory via CATSEYE_GRAMMAR_DIR
GRAMMAR_DIR="${CATSEYE_GRAMMAR_DIR:-$HOME/.tree-sitter}"
mkdir -p "$GRAMMAR_DIR"

echo "Installing tree-sitter grammars..."
echo "Destination: $GRAMMAR_DIR"
echo ""

# Method 1: Via tree-sitter CLI (recommended)
if command -v tree-sitter &>/dev/null; then
	for lang in javascript typescript rust gleam; do
		echo "  Installing $lang (via tree-sitter CLI)..."
		if tree-sitter install-language "$lang" 2>/dev/null; then
			echo "    ✓ $lang installed"
		else
			echo "    ✗ $lang failed (try: npx tree-sitter install-language $lang)"
		fi
	done
else
	# Method 2: Via npm packages
	echo "tree-sitter CLI not found, using npm fallback..."
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
fi

echo ""
echo "✓ Grammar installation complete"
echo "  Location: $GRAMMAR_DIR"
echo "  Set CATSEYE_GRAMMAR_DIR to customize"
echo ""
echo "Supported languages: javascript, typescript, rust, gleam, svelte, ocaml"
