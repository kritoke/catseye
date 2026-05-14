# Svelte Support

**Status:** Proposed  
**Priority:** Future  
**Depends on:** None

## Goal

Add Svelte (`.svelte`) file scanning to Catseye, enabling security analysis of Svelte web applications with the same taint-tracking pipeline used for Crystal and Gleam.

## Architecture Fit

Catseye's pipeline is language-agnostic: `Extractor → Security Node JSON → Engine`. Adding Svelte means building a new extractor that emits the same JSON schema. The engine rules would need Svelte-specific sinks added.

## Security-Relevant Surface in Svelte

The interesting attack surface lives in `<script>` blocks (JavaScript/TypeScript):

| Pattern | Rule | Severity |
|---------|------|----------|
| `fetch()` / `axios` with user-controlled URLs | SSRF | High |
| `{@html expr}` with tainted data | XSS | Critical |
| `element.innerHTML = tainted` | XSS | Critical |
| `document.location`, `window.location` | Open Redirect | Medium |
| `eval()`, `Function()`, `setTimeout(string)` | Code Injection | Critical |
| `$page.url.searchParams` / `$app/stores` | Taint Source | — |
| Missing CSP headers in SvelteKit config | MissingHeaders | Low |

## Options

### Option A: Tree-sitter (Preferred)

A Nim extractor using `tree-sitter-svelte` + `tree-sitter-javascript`, following the same pattern as the existing Gleam extractor (`src/extractor/gleam_extractor.nim`).

**How it works:**
1. Parse `.svelte` file with `tree-sitter-svelte` grammar
2. Walk the CST to find `<script>` blocks
3. Parse script content with `tree-sitter-javascript` grammar
4. Extract calls, assignments, definitions → Security Node JSON
5. Taint sources: `$page`, `url.searchParams`, `event.params`, `FormData`, etc.

**Pros:**
- **No new runtime.** Stays in Nim, same as Gleam extractor
- Consistent with existing architecture
- `tree-sitter-svelte` v1.0.2 exists (MIT, npm/PyPI/crates.io)
- `tree-sitter-javascript` is battle-tested
- Grammars compile to `.so` files, loaded at runtime
- No Node.js dependency needed

**Cons:**
- `tree-sitter-svelte` is relatively young (20 stars, 10 open issues)
- Multi-language files (HTML + JS + CSS) require nested parsing
- May need to handle TypeScript inside `<script lang="ts">` blocks separately

**Implementation:**
- `src/extractor/svelte_extractor.nim` — Nim + tree-sitter walker
- New grammar: `tree-sitter-svelte` + `tree-sitter-javascript` added to flake.nix
- New taint sources for Svelte: `$page`, `$app/stores`, `event`, `params`
- New sinks: `{@html}`, `innerHTML`, `fetch`, `eval`
- `justfile`: `just scan-svelte <dir>`
- CLI: `--lang svelte` filter

**Estimated effort:** 2-3 days

### Option B: svelte/compiler API

A Node.js script using Svelte's official `parse()` from `svelte/compiler`.

**How it works:**
1. Call `parse(source, { modern: true })` from `svelte/compiler`
2. Walk the returned AST, focusing on `<script>` block content
3. The JS inside is already parsed via Acorn by Svelte's compiler
4. Extract calls, assignments, definitions → Security Node JSON

**Pros:**
- Official parser, always up-to-date with Svelte syntax
- Handles multi-language files natively (parses `<script>` via Acorn internally)
- Supports Svelte 5's new runes syntax (`$state`, `$derived`, `$effect`)
- Most accurate AST representation

**Cons:**
- **Adds Node.js as a 4th runtime** (Nim, Crystal, Gleam/Erlang, now Node)
- Requires `npm install svelte` as a dependency
- Inconsistent with existing extractor pattern (all others are compiled binaries)
- Node.js version management becomes a concern in nix shell
- Increases flake.nix complexity

**Estimated effort:** 1-2 days (simpler parsing, but more infra overhead)

## Recommendation

**Option A (tree-sitter) is preferred.** It keeps the project in Nim and doesn't add another runtime dependency. The Gleam extractor proves the tree-sitter pattern works well. The only risk is `tree-sitter-svelte` grammar maturity, which can be mitigated with a quick spike to verify it parses `<script>` blocks correctly.

A prototype spike should:
1. Compile `tree-sitter-svelte` to a `.so`
2. Parse 3-4 real `.svelte` files (from SvelteKit projects)
3. Verify the CST contains navigable `<script>` block content
4. If it works → proceed with Option A
5. If `<script>` blocks are opaque blobs → fall back to Option B
