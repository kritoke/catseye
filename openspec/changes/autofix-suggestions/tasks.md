# Autofix / Suggested Fixes — Tasks

## Phase 1: Core Infrastructure

- [x] 1.1 Add `fix_template : string option` to `sink_def` in `types.ml`
- [x] 1.2 Parse `fix` from KDL sink nodes in `loader.ml` (supports both `fix="..."` property and `fix "..."` child syntax)
- [x] 1.3 Add `instantiate_fix` to `interpreter.ml` — substitute `{arg0}`, `{arg1}`, `{sink}` in template
- [x] 1.4 Wire `fix_template` → `instantiate_fix` → `Finding.suggestion` in sink matching paths (flat + CFG)

## Phase 2: Output Rendering

- [x] 2.1 Terminal: show `💡 Suggestion: <fix>` after findings with suggestions in `orchestrator.ml`
- [x] 2.2 JSON: `suggestion` field serialized in `finding.ml` encode/decode
- [x] 2.3 SARIF: suggestion included in `properties` object of SARIF results

## Phase 3: Rule Updates

- [x] 3.1 Add `fix` templates to `ssrf.kdl` sinks (21 sinks)
- [x] 3.2 Add `fix` templates to `path_traversal.kdl` sinks (11 sinks)
- [x] 3.3 Add `fix` templates to `sql_injection.kdl` sinks (8 sinks)
- [x] 3.4 Add `fix` templates to `command_injection.kdl` sinks (14 sinks)
- [x] 3.5 Add `fix` templates to `open_redirect.kdl` sinks (3 sinks)
- [x] 3.6 Add `fix` templates to `deserialization.kdl` sinks (7 sinks)
- [x] 3.7 Add `fix` templates to `hardcoded_secrets.kdl` sinks (6 sinks)
- [x] 3.8 Add `fix` templates to `ldap_xml_injection.kdl` sinks (4 sinks)
- [x] 3.9 Add `fix` templates to `missing_timeout.kdl` sinks (2 sinks)
- [x] 3.10 Add `fix` templates to `redos.kdl` sinks (4 sinks)
- [x] 3.11 Add `fix` templates to `scent_leakage.kdl` sinks (20 sinks)
- [x] 3.12 Add `fix` templates to `weak_crypto.kdl` sinks (10 sinks)

**Total: 103 fix templates across 12 rules, 100% sink coverage.**

## Phase 4: Testing & Validation

- [x] 4.1 Unit test: `instantiate_fix` with single and multi-arg templates (in `kdl_precision_test.ml`)
- [x] 4.2 Unit test: KDL parsing of `fix` property (in `kdl_precision_test.ml`)
- [x] 4.3 E2E: scan `test/samples/vulnerable.cr` — suggestions appear in terminal output
- [x] 4.4 E2E: scan with `--format json` — `suggestion` field populated
- [x] 4.5 All existing tests still pass (23 findings, 0 safe, 5 smells)
- [x] 4.6 Scan real projects — verified against 10 Crystal + 1 Gleam, no crashes, suggestions reasonable

## Phase 5: Bug Fixes (discovered during validation)

- [x] 5.1 Fix `loader.ml` — `fix` was read as KDL property but rules use child node syntax. Now supports both.
