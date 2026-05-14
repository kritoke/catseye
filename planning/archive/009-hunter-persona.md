# Hunter Persona — UX Planning

**Status:** Phase 1 ✅ Phase 2 ✅ — Phase 3 (stretch) remaining
**Target:** OCaml rewrite (`src/ocaml/`)
**Goal:** Transform Catseye's terminal output from generic security-tool speak into a "Hunter" persona — a cat stalking prey through the tall grass of your codebase.

---

## The Core Idea

Security tools sound like corporate reports. Catseye should sound like a cat.
The output should feel alive — like watching a predator silently scan, stalk, and either hiss at danger, meow at something suspicious, or purr when the coast is clear.

This isn't cosmetics. Developers reach for tools they *enjoy*. Personality is the difference between "ugh, I have to run the scanner" and "let me see what the cat found."

---

## Severity Levels (The Catseye Lexicon)

Replace the generic `critical/high/medium/low` in terminal output with cat-themed levels:

| Internal Severity | Catseye Level | Icon | ANSI Color | When Used                                      |
|-------------------|---------------|------|------------|-------------------------------------------------|
| Critical          | **Hiss**      | 🐱⚡  | Red        | Confirmed dangerous vuln (SQLi, cmd injection)  |
| High              | **Hiss**      | 🐱⚡  | Red        | High-confidence dangerous finding               |
| Medium            | **Meow**      | 🐾   | Yellow     | Suspicious pattern, worth investigating          |
| Low               | **Meow**      | 🐾   | Yellow     | Minor issue, low risk                            |
| Info / Safe       | **Purr**      | 😸   | Green      | No issues found, clean scan                      |

**Important:** The internal JSON/SARIF output keeps standard severity names (`critical`, `high`, etc.). The cat levels are a *terminal presentation layer only*. This preserves CI/GitHub compatibility while giving developers a fun daily-driver experience.

---

## Terminal Output Design

### Banner (scan start)

Current (in `orchestrator.ml` → `print_banner`):
```
╔══════════════════════════════════════╗
║            Catseye v0.3.0           ║
╚══════════════════════════════════════╝
  Target:   ./src
  Files:    66 Crystal, 12 Gleam
  Engine:   OCaml (taint v3)
```

New:
```
 ╭──────────────────────────────────────────╮
 │  🐈‍⬛  Catseye v0.3.0                     │
 │     The Hunter enters the tall grass...  │
 ╰──────────────────────────────────────────╯
  Target:   ./src
  Files:    66 Crystal, 12 Gleam
  Scent:    Fresh code detected
```

The "Scent" line is a small atmospheric touch — randomized from a pool:

- `Fresh code detected`
- `Many files to patrol`
- `Something rustles in the undergrowth...`
- `The codebase stirs.`
- `Scent trail picked up.`
- `The tall grass parts...`

### Extraction phase (stalking)

Current (in `orchestrator.ml` → `extract_with_log`):
```
→ Extracting: src/controller.cr
```

New:
```
  🐾 Stalking src/controller.cr
  🐾 Stalking src/models/user.cr
  🐾 Stalking src/views/index.gleam
```

### Analysis phase (hunting)

Current (in `orchestrator.ml` → `run`):
```
→ Running analysis engine (5337 nodes)...
```

New:
```
  👀 Watching... 5,337 nodes to inspect
  🎯 Pouncing on taint flows...
```

### Findings (prey spotted)

Current:
```
[CommandInjection] High  src/controller.cr:42
  Found os.command() with tainted input from request.params
      ← Source: request.params enters scope (controller.cr:15)
      ↓  Sink: os.command(cmd) (controller.cr:42)
```

**Hiss** (Critical/High):
```
  🐱⚡ HISS  [CommandInjection]  src/controller.cr:42
       Found os.command() with tainted input from request.params
       ← Source: request.params enters scope (controller.cr:15)
       ↓  Sink: os.command(cmd) (controller.cr:42)
```

**Meow** (Medium/Low):
```
  🐾 MEOW  [WeakCrypto]  src/auth.cr:28
       MD5 used for password hashing — consider bcrypt
```

### Clean scan (purr)

Current:
```
No issues found across 66 file(s). ✨
```

New:
```
  😸 PURR  The codebase is clean.
       66 files patrolled. Nothing lurking in the grass.

  The Hunter rests.
```

### Summary line (scan end)

If findings exist:
```
──────────────────────────────────────────────────────────────
  🐱 Found 3 Hiss, 2 Meow across 66 files.
  The Hunter has prey. Review the findings above.
```

Clean:
```
──────────────────────────────────────────────────────────────
  😸 All clear. 66 files. 0 prey.
```

---

## Implementation Plan

### Phase 1: Severity remap + icons + narrative (core change)

All changes in `src/ocaml/lib/catseye_cli/orchestrator.ml`.

- [x] Add `catseye_level : string -> string` function (also handles capitalized variants)
- [x] Add `catseye_icon : string -> string` function (also handles capitalized variants)
- [x] Add `scent_lines : string array` const + random selection using `Random.self_init ()` + `Random.int`
- [x] Update `print_banner`:
  - `print_banner_persona` — round-cornered box + cat emoji + subtitle + scent line
  - `print_banner_plain` — original square box style preserved for `--no-persona`
- [x] Update `extract_with_log`: `🐾 Stalking` when persona on, `→ Extracting:` when off
- [x] Update analysis phase print: `👀 Watching...` + `🎯 Pouncing on taint flows...`
- [x] Update `print_finding`: uses `catseye_level` + `catseye_icon` + styled colors
- [x] Update clean scan message: `😸 PURR The codebase is clean.` + `The Hunter rests.`
- [x] Update summary line: `🐱 Found X Hiss, Y Meow` with `count_by_severity` helper

### Phase 2: Opt-out flag

- [x] Add `persona : bool` field to `Config.t` (default `true`) — `config.ml`
- [x] Add `--no-persona` to `args.ml` parser with help text
- [x] Gate all Hunter output behind `if config.persona then ... else ...` — banner, extraction, analysis, findings, summary
- [x] When persona is off: plain professional style preserved (square box, `→ Extracting:`, standard severity names)
- [x] Support `[persona] enabled = false` in `.catseye.toml` via `config.ml` `load_toml`

### Phase 3: Future polish (stretch goals)

- [ ] Animate the "stalking" phase with `\r` overwrites if terminal supports it (show files scanning in-place)
- [ ] Color-blind accessible mode: use text labels (HISS/MEOW/PURR) prominently even without relying on color
- [ ] Sound effect: `--sound` flag triggers ASCII bell on Hiss findings (genuinely optional, probably too much)

---

## What stays the same

| Component                              | Change? | Reason                                      |
|----------------------------------------|---------|---------------------------------------------|
| JSON output (`--format json`)          | **No**  | Machine-readable, CI pipelines              |
| SARIF output (`--format sarif`)        | **No**  | GitHub Code Scanning, standard format       |
| Markdown output (`--format markdown`)  | **No**  | Reports, documentation                      |
| `Finding.t` record                     | **No**  | `severity` field keeps standard names        |
| Engine severity strings                | **No**  | Engine uses `critical`/`high`/`medium`/`low` |
| Flow traces                            | **Minor** | Same data, same arrows (`←` source, `↓` sink) |
| `Sarif.to_sarif`                       | **No**  | Structured output is sacred                  |
| `Markdown.to_markdown`                 | **No**  | Structured output is sacred                  |

The Hunter persona is **terminal-only** and **opt-out via `--no-persona`**. It never leaks into structured output formats.

---

## Design Principles

1. **Personality, not cringe.** The cat theme should feel natural and sparse — a few well-placed touches, not emoji soup. Less is more.
2. **Signal first.** The actual vulnerability info (file, line, rule, flow) must remain instantly scannable. The persona dresses the frame, it doesn't obscure the picture.
3. **Structured output is sacred.** JSON/SARIF/Markdown never see the cat. Those are for machines and audits.
4. **Opt-out is clean.** `--no-persona` gives you the old plain style. No judgment.
5. **The Hunter has stakes.** "Hiss" means *danger*. "Meow" means *pay attention*. "Purr" means *you're safe*. The mapping makes emotional sense, not just thematic sense.

---

## Related Features

The Hunter persona is the foundation layer. These features build on top of it:

| Feature | Planning Doc | Description |
|---------|-------------|-------------|
| **Predator Vision** | `planning/predator-vision.md` | Reachability-first analysis with attack surface heatmap |
| **Crow's Nest** | `planning/crows-nest.md` | Deep supply chain tracking (CVE + staleness + reachability) |

Both features reuse the Hiss/Meow/Purr severity levels and the terminal persona styling defined here.
