# Svelte Support Openspec

## Context

Svelte support in Catseye provides security analysis for `.svelte` files with:
1. Two-pass parsing: tree-sitter-svelte + JS/TS grammar for `<script>` blocks
2. XSS/SSRF detection for `{@html}` directives and dynamic content
3. Framework confusion detection (Svelte 4→5 migration patterns)

## Current State

### Implemented
- [x] File discovery (`.svelte` extension)
- [x] Two-pass parsing via tree-sitter XML bridge
- [x] Svelte→JS/TS extraction for `<script>` blocks
- [x] Security rules: XSS via `{@html}`, SSRF patterns
- [x] AI lint rules for Svelte 4→5 migration
- [x] Framework confusion detection (React hooks, Vue directives)

### Known Issues / False Positives

#### 1. `.svelte.ts` Files (RESOLVED in v0.4.2)
Svelte 5 stores as `.svelte.ts` files contain `$state` runes that confuse the JS parser, producing false positive `LargeClass` findings with LOC counts of 999,999.

**Status**: ✅ **Fixed** - `.svelte.ts` files are now excluded from scanning.

#### 2. `{@html}` Detection Accuracy
Current detection may miss:
- Safe HTML from sanitized sources
- Context-aware XSS (attribute vs text injection)

#### 3. Svelte 5 Runes
Limited support for Svelte 5 patterns:
- `$state`, `$derived`, `$effect` rune detection
- Stores as callback props migration detection
- `$:` reactive statements (Svelte 4 syntax in Svelte 5 files)

## Proposed Features

### 1. Svelte 5 Rune Detection
Expand AI lint rules to cover Svelte 5 patterns:
- [ ] `$state` usage patterns
- [ ] `$derived` computed values
- [ ] `$effect` side effects
- [ ] `$props` component props

### 2. SvelteKit Specific Rules
Add rules for SvelteKit-specific patterns:
- [ ] `+page.server.ts` data loading security
- [ ] Form actions CSRF
- [ ] SSR context isolation

### 3. Enhanced `{@html}` Analysis
Improve XSS detection:
- [ ] Taint tracking through template expressions
- [ ] Context-aware injection detection
- [ ] Sanitizer identification (DOMPurify, etc.)

### 4. Test Fixtures
Add more comprehensive test samples:
- [ ] Svelte 4 stores as runes
- [ ] `{@html}` with dynamic content
- [ ] SvelteKit form actions
- [ ] Component props patterns

## Implementation Plan

### Phase 1: Test Fixtures
- [ ] Create `test/samples/svelte/svelte5-runes.svelte` - Svelte 5 patterns
- [ ] Create `test/samples/svelte/html-directive.svelte` - `{@html}` XSS patterns
- [ ] Update existing tests

### Phase 2: Svelte 5 Rune Detection
- [ ] Add rune detection to `svelte_rules.ml`
- [ ] Add migration suggestions
- [ ] Add deprecation warnings for Svelte 4 patterns

### Phase 3: Enhanced XSS Analysis
- [ ] Taint propagation through template expressions
- [ ] Context-aware injection detection
- [ ] Sanitizer identification

## Success Criteria
- `.svelte` files scan correctly without FPs
- XSS via `{@html}` is detected accurately
- Svelte 4→5 migration warnings are helpful
- No `.svelte.ts` files cause false positives