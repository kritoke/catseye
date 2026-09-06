## Nim AI-linter detector fixture — positive and negative cases per detector.
import std/[os, json, strutils]

# ── nim-unused-param: `unused` never referenced ─────────────────────
proc posUnused(a: string, unused: int): string =
  result = "x" & a

# negative: both params used
proc negUnused(a: string, b: int): string =
  result = a & $b

# ── nim-shadowed-var: inner `value` rebinding an outer let ──────
proc posShadow(): int =
  let value = 10
  let value = value + 1
  result = value

# negative: distinct names
proc negShadow(value: int): int =
  let doubled = value * 2
  result = doubled

# ── nim-empty-rescue: except body only discard ──────────────────────
proc posEmptyRescue() =
  try:
    echo readFile("/etc/hostname")
  except IOError:
    discard

# negative: except body logs
proc negEmptyRescue() =
  try:
    echo readFile("/etc/hostname")
  except IOError as e:
    echo "failed: ", e.msg

# ── nim-debug-leftover: bare debugEcho shipped ──────────────────────
proc posDebug(x: int): int =
  debugEcho("trace ", x)
  result = x

# ── nim-deprecated-api: existsFile / existsDir / writeln ────────────
proc posDeprecated(path: string): bool =
  if existsFile(path):
    writeln("found file")
    result = true
  elif existsDir(path):
    result = true
  else:
    result = false

# negative: current spellings
proc negDeprecated(path: string): bool =
  if fileExists(path) or dirExists(path):
    echo "found"
    result = true
  else:
    result = false

# ── nim-mass-assignment: parseJson result → .to(Object) ─────────────
type User = object
  name: string
  role: string

proc posMassAssignment(data: string): User =
  let parsed = parseJson(data)
  result = parsed.to(User)

# negative: field extraction
proc negMassAssignment(data: string): string =
  let parsed = parseJson(data)
  result = parsed["name"].getStr()

# ── nim-eval-usage: runtime string metaprogramming ──────────────────
proc posEval(exprStr: string): int =
  result = len(parseExpr(exprStr).repr)

# ── no-FP guard: ONLY system builtins — zero hallucinated-function ──
proc systemBuiltinsOnly(s: string, xs: seq[int]): int =
  let total = len(xs)
  if contains(s, "x") and startsWith(s, "a") and endsWith(s, "z"):
    echo "hit"
  for x in xs:
    total.add 0   # placeholder never executed; add() is a system builtin too
  open("/dev/null")
  raise newException(IOError, "done")
