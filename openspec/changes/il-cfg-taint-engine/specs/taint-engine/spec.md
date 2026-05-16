## MODIFIED Requirements

### Requirement: CFG-based taint propagation
The taint engine SHALL propagate taint through the CFG using forward dataflow analysis. Each basic block computes taint state from predecessors and passes it to successors. Branches create separate taint states.

#### Scenario: Taint does not flow through dead branch
- **WHEN** taint source is in the else-branch and sink is in the then-branch
- **THEN** no finding is produced (taint does not cross branches)

#### Scenario: Taint merges after branch
- **WHEN** a variable is tainted in one branch and clean in another
- **AND** both branches merge into a single block
- **THEN** the variable is considered tainted at the merge (may-analysis)

### Requirement: Field-sensitive taint tracking
The engine SHALL track taint on field-sensitive lvalues. `params.url` being tainted does not imply `params.body` is tainted.

#### Scenario: Specific field tainted
- **WHEN** `LVField (LVVar "params", "url")` is marked as a taint source
- **THEN** only `params.url` and derived lvalues are tainted, not `params.body`

### Requirement: Arg-position sink matching
The engine SHALL use `arg=N` from KDL rules when checking sinks. Only tainted data in the specified argument position triggers a finding.

#### Scenario: Tainted arg at wrong position
- **WHEN** sink declares `arg=0` and taint is in arg 1
- **THEN** no finding produced

### Requirement: Backward compatible with existing rules
All existing KDL rules (12 files) SHALL produce identical results when run through the CFG engine. Rules without `arg` or `$` behave exactly as before.

#### Scenario: All 12 KDL rules unchanged
- **WHEN** the 12 existing KDL rule files are parsed
- **THEN** no parsing errors occur and all rules produce the same findings as the flat engine
