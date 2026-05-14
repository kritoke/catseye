# OCaml Rewrite — Engine Review TODO

Use this checklist when reviewing against alternative engines (Semgrep, CodeQL, etc.)

## Before You Start

- [ ] Identify your reference codebase (largest Crystal project for benchmark)
- [ ] Clone/checkout relevant Semgrep/CodeQL documentation
- [ ] Ensure current catseye is built and working

## Benchmark Current System

```bash
# Time a full scan
time just scan-crystal <your-large-project> 2>&1 | tee /tmp/catseye-timing.txt

# Run with instrumentation (add to catseye.nim temporarily)
# Or use: /usr/bin/time -v just scan-crystal <project>
```

**Record**:
- Total time: ___ seconds
- Files scanned: ___
- Nodes extracted: ___
- Findings: ___

## Review: Semgrep Taint Analysis

**Study material**:
- https://semgrep.dev/docs/taint-traces/
- https://semgrep.dev/docs/writing-rules/pattern-syntax/
- Semgrep rules repository (search for `taint`)

**Questions to answer**:
1. How does Semgrep model taint sources vs sinks?
2. Can Semgrep track taint through function returns?
3. How does Semgrep handle sanitizers?
4. What output formats does Semgrep produce?
5. Can Semgrep track field-sensitive taint (e.g., `req.params["url"]`)?

**Findings**:

| Aspect | Catseye | Semgrep | Gap? |
|--------|---------|---------|------|
| Taint sources | hardcoded list + config | ? | ? |
| Sinks | hardcoded list | ? | ? |
| Sanitizers | hardcoded list + config | ? | ? |
| Return tracking | yes | ? | ? |
| Field sensitivity | partial | ? | ? |
| Inter-procedural | yes | ? | ? |

## Review: CodeQL Taint Tracking

**Study material**:
- CodeQL documentation: taint tracking
- CodeQL queries for security (GitHub Advanced Security)

**Questions to answer**:
1. How does CodeQL model taint propagation?
2. Does CodeQL use fixed-point or single-pass?
3. How does CodeQL handle sanitizers?
4. What output does CodeQL produce?

**Findings**:

| Aspect | Catseye | CodeQL | Gap? |
|--------|---------|--------|------|
| Propagation model | fixed-point | ? | ? |
| Sanitizers | hardcoded list | ? | ? |
| Inter-procedural | yes | ? | ? |
| Graph output | linear | ? | ? |

## Decision Points

After completing the reviews, update `STATUS.md` with decisions on:

1. **Map vs List TaintDB**: Based on semantics comparison
   - [ ] Decision: ___ (Keep Map / Revert to List / Hybrid)

2. **Fixed-point correctness**: Based on Semgrep/CodeQL comparison
   - [ ] Decision: ___ (Keep fixed-point / Change approach)

3. **Graph vs linear flow**: Based on output format needs
   - [ ] Decision: ___ (Keep graph / Revert to linear / Both)

4. **Incremental vs batch**: Based on benchmark results
   - [ ] Decision: ___ (Incremental / Batch / Hybrid)

5. **Additional patterns**: Based on engine comparison
   - [ ] Pattern: ___
   - [ ] Pattern: ___

## Report Template

After completing review, fill in `ENGINE-REVIEW.md`:

```markdown
# Engine Review Report

## Date: 2026-XX-XX

## Benchmark Results

[Insert timing data]

## Semgrep Comparison

[Findings from Semgrep review]

## CodeQL Comparison

[Findings from CodeQL review]

## Decisions

[Updated decisions based on review]

## Recommendations

[Recommendations for OCaml implementation]
```

---

*Checklist created: 2026-05-09*
*To be used by: User performing engine review*