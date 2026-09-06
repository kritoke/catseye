## Fixture: file name contains shell metacharacters.
## Regression guard for tree-sitter invocation quoting (crystal_ts.ml / nim_mapper).
## If quoting regresses, the embedded `touch` runs and creates a marker file.
import os
proc fixture() =
  let p = os.getEnv("X")
  discard os.execShellCmd(p)
