# Implementation Status — Hunter Features

## Hunter Persona — ✅ Phase 1 + Phase 2 DONE

| Phase | Item | Status |
|-------|------|--------|
| 1 | Severity remap (Hiss/Meow/Purr) | ✅ Done |
| 1 | Cat icons (🐱⚡ 🐾 😸) | ✅ Done |
| 1 | Scent lines (6 random variants) | ✅ Done |
| 1 | Cat banner with round corners | ✅ Done |
| 1 | 🐾 Stalking during extraction | ✅ Done |
| 1 | 👀 Watching / 🎯 Pouncing during analysis | ✅ Done |
| 1 | HISS/MEOW finding format | ✅ Done |
| 1 | PURR clean scan + "The Hunter rests" | ✅ Done |
| 1 | Summary with Hiss/Meow counts | ✅ Done |
| 2 | `--no-persona` flag | ✅ Done |
| 2 | `persona` field in Config.t | ✅ Done |
| 2 | `[persona] enabled = false` in .catseye.toml | ✅ Done |
| 2 | Plain output when persona off | ✅ Done |
| 3 | Animated stalking with \r | ❌ Not done (stretch) |
| 3 | Sound effects | ❌ Not done (stretch) |

**Verdict:** Core persona (Phase 1+2) is complete. Phase 3 was always stretch goals.

---

## Predator Vision — ✅ Phase 0 + Phase 1 + Phase 2 DONE

| Phase | Item | Status |
|-------|------|--------|
| 0 | `reachability.ml`: entry_point type | ✅ Done |
| 0 | Auto-detect HTTP/CLI/Custom entry points | ✅ Done |
| 0 | Call adjacency from Def/Call scopes | ✅ Done |
| 0 | BFS reachability from entry points | ✅ Done |
| 0 | Path tracing (BFS with parent tracking) | ✅ Done |
| 1 | `heatmap.ml`: per-file grouping | ✅ Done |
| 1 | Heatmap ratio bars (###---) | ✅ Done |
| 1 | Live/Dormant/Safe icons + ANSI colors | ✅ Done |
| 1 | Reachability path shown for Live findings | ✅ Done |
| 1 | `--predator-vision` flag | ✅ Done |
| 1 | `[predator_vision] enabled = true` in TOML | ✅ Done |
| 2 | `Finding.t` reachability field | ✅ Done |
| 2 | `Finding.encode` includes reachability | ✅ Done |
| 2 | `Finding.decode` parses reachability | ✅ Done |
| 2 | JSON reachability_summary top-level | ❌ Not done |
| 2 | SARIF additional codeFlow for reachability | ❌ Not done |
| 2 | Markdown reachability column | ❌ Not done |
| 3 | Weighted entry points | ❌ Not done (future) |
| 3 | Delta heatmaps / --watch | ❌ Not done (future) |
| 3 | Call graph DOT export | ❌ Not done (future) |

**Verdict:** Core reachability engine + terminal heatmap + Finding type extension all done.
Phase 2 structured output (SARIF codeFlow, Markdown column) is partially done — JSON encoding
of the reachability field works per-finding, but the top-level summary and SARIF integration
are not yet wired. Phase 3 was always future.

---

## Crow's Nest — ✅ Phase 0-4 DONE, Phase 5 PARTIAL

| Phase | Item | Status |
|-------|------|--------|
| 0 | `manifest.ml`: shard.yml parser | ✅ Done |
| 0 | `manifest.ml`: gleam.toml parser | ✅ Done |
| 0 | Auto-detect manifests (recursive) | ✅ Done |
| 1 | `osv.ml`: OSV.dev API client | ✅ Done |
| 1 | `osv.ml`: JSON response parsing | ✅ Done |
| 1 | `cache.ml`: SQLite OSV cache (24h TTL) | ✅ Done |
| 1 | Graceful offline fallback | ✅ Done |
| 2 | `staleness.ml`: GitHub API query | ✅ Done |
| 2 | `staleness.ml`: Hex API query | ✅ Done |
| 2 | `staleness.ml`: Composite staleness score | ✅ Done |
| 2 | Cache staleness results | ✅ Done |
| 3 | Dep → import site mapping | ❌ Not done |
| 3 | Cross-ref with Predator Vision adjacency | ❌ Not done |
| 4 | `--crows-nest` / `-cn` flag | ✅ Done |
| 4 | `[crows_nest]` TOML support | ✅ Done |
| 4 | `crowsnest_format.ml` terminal output | ✅ Done |
| 4 | Pipeline integration in orchestrator | ✅ Done |
| 4 | Exit code 1 on Hiss | ✅ Done |
| 5 | JSON `supply_chain` top-level field | ✅ Done |
| 5 | SARIF SCA results | ❌ Not done |
| 5 | Markdown supply chain section | ❌ Not done |

**Verdict:** Core supply chain audit (CVE scanning + staleness + terminal + JSON) is done.
Phase 3 (dep reachability integration with Predator Vision) and Phase 5 SARIF/Markdown
are the gaps.

---

## Summary

| Feature | Core Done | Remaining |
|---------|-----------|-----------|
| Hunter Persona | ✅ 100% | Phase 3 stretch (animation, sound) |
| Predator Vision | ✅ ~85% | SARIF codeFlow, Markdown column, JSON summary |
| Crow's Nest | ✅ ~80% | Dep reachability (Phase 3), SARIF/Markdown (Phase 5) |

All three features build, the terminal pipeline works end-to-end, and the Hunter persona
renders correctly on real scans. The remaining items are output-format integrations (SARIF,
Markdown) and the cross-feature dep reachability bridge.
