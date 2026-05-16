## ADDED Requirements

### Requirement: Sink argument position matching
KDL sinks SHALL accept an optional `arg=N` attribute. When present, the engine only flags the finding if tainted data flows into the specified argument position (0-indexed).

#### Scenario: arg=0 on HTTP::Client.get
- **WHEN** a KDL rule declares `sink "HTTP::Client.get" arg=0`
- **AND** taint flows into the second argument but not the first
- **THEN** no finding is produced

#### Scenario: arg=0 with tainted first arg
- **WHEN** a KDL rule declares `sink "HTTP::Client.get" arg=0`
- **AND** tainted data is the first argument
- **THEN** the finding is produced

#### Scenario: No arg specified matches any argument
- **WHEN** a KDL rule declares `sink "HTTP::Client.get"` without `arg`
- **THEN** any tainted argument triggers the finding (backward compatible)

### Requirement: Metavariable receiver matching
KDL sink/source/sanitizer names starting with `$` SHALL match any receiver prefix. The `$` captures everything before the first `.`.

#### Scenario: $client.get matches multiple receivers
- **WHEN** a KDL rule declares `sink "$client.get"`
- **THEN** it matches `http.get(...)`, `client.get(...)`, `conn.get(...)`, and `my_client.get(...)`

#### Scenario: Full name without $
- **WHEN** a KDL rule declares `sink "HTTP::Client.get"` (no `$`)
- **THEN** it matches only the exact name (backward compatible)
