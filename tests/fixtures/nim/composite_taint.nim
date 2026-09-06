## Composite-argument taint fixture.
## Guards composite-arg-taint-propagation: variables inside binary-operator
## arguments (string concat) must reach sinks.
## Variables are seeded via real taint sources (os.getEnv) so the only thing
## under test is whether taint flows THROUGH the composite argument.
import os
import std/httpclient

proc cmdViaConcat() =
  ## "ls " & userInput is an EBinOp arg — taint from getEnv must reach execShellCmd
  let userInput = os.getEnv("USER_INPUT")
  discard os.execShellCmd("ls " & userInput)

proc cmdViaTripleConcat() =
  ## nested composites surface every variable
  let dir = os.getEnv("TARGET_DIR")
  let name = os.getEnv("TARGET_FILE")
  let code = os.execCmd("cat " & dir & "/" & name)
  echo code

proc ssrfViaConcat() =
  ## getContent(base & suffix) — SSRF via composite URL
  let base = os.getEnv("API_BASE")
  let suffix = os.getEnv("API_PATH")
  let client = newHttpClient()
  echo client.getContent(base & suffix & "/api")
