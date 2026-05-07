## Catseye Gleam Extractor — Nim
##
## Parses .gleam files to find function calls, let bindings, and definitions.
## Emits Security Node JSON compatible with the Gleam logic engine.
##
## Usage: nim c -r src/extractor/gleam_extractor.nim <file.gleam>

import std/[os, json, strutils, strformat, sets, sequtils]

type
  ArgNode = object
    argType: string
    value: string

  SecNode = object
    typ: string
    name: string
    args: seq[ArgNode]
    line: int
    taint: bool
    file: string

const TaintSources = toHashSet([
  "request", "req", "params", "get_body",
  "io.get_line", "dynamic.unsafe_coerce",
])

const SkipCalls = toHashSet([
  "list.map", "list.filter", "list.each", "list.any", "list.fold",
  "list.append", "list.length", "list.reverse", "list.filter",
  "result.try", "result.map", "result.then", "result.is_ok",
  "result.is_err", "result.unwrap",
  "option.map", "option.unwrap", "option.is_some",
  "io.println", "io.print", "io.debug",
  "string.concat", "string.join", "string.slice", "string.split",
  "string.starts_with", "string.ends_with", "string.contains",
  "int.to_string", "int.parse", "float.to_string",
  "dict.new", "dict.insert", "dict.get",
  "echo", "println",
])

const IdentChars = {'a'..'z', '0'..'9', '_'}
const IdentStart = {'a'..'z', '_'}

# ── Helpers ────────────────────────────────────────────────────────────

proc isAllDigits(s: string): bool =
  for c in s:
    if c notin Digits: return false
  true

proc isIdent(s: string): bool =
  s.len > 0 and s[0] in IdentStart and s.allCharsInSet(IdentChars)

proc classifyArg(token: string): ArgNode =
  let t = token.strip()
  if t.len == 0:
    return ArgNode(argType: "unknown", value: "")
  if t[0] == '"':
    let val = if t.len > 1: t[1..^2] else: ""
    return ArgNode(argType: "literal", value: val)
  if t.isAllDigits():
    return ArgNode(argType: "literal", value: t)
  if t in ["True", "False", "Nil", "nil", "Ok", "Error"]:
    return ArgNode(argType: "literal", value: t)
  if '.' in t:
    return ArgNode(argType: "call", value: t)
  if t.isIdent():
    return ArgNode(argType: "var", value: t)
  return ArgNode(argType: "unknown", value: t[0..min(80, t.high)])

proc parseArgs(argsStr: string): seq[ArgNode] =
  let s = argsStr.strip()
  if s.len == 0: return @[]
  var depth = 0
  var current = ""
  for c in s:
    case c
    of '(', '[', '{':
      depth.inc; current.add(c)
    of ')', ']', '}':
      depth.dec; current.add(c)
    of ',':
      if depth == 0:
        let token = current.strip()
        if token.len > 0: result.add(classifyArg(token))
        current = ""
      else:
        current.add(c)
    else:
      current.add(c)
  let token = current.strip()
  if token.len > 0: result.add(classifyArg(token))

proc extractCallName(s: string; start: int): (string, int) =
  ## Extract a dotted identifier starting at position start.
  ## Returns (name, endPos).
  var i = start
  while i < s.len:
    if s[i] in IdentChars or s[i] == '.':
      i.inc
    else:
      break
  return (s[start..<i], i)

proc extractBalanced(s: string; openPos: int): (string, int) =
  ## Extract content between balanced parens starting at openPos.
  ## Returns (content, closePos).
  var depth = 0
  var i = openPos
  while i < s.len:
    case s[i]
    of '(', '[', '{': depth.inc
    of ')', ']', '}':
      depth.dec
      if depth == 0:
        return (s[openPos+1..<i], i)
    else: discard
    i.inc
  return ("", s.len)

# ── Extraction ─────────────────────────────────────────────────────────

proc extractGleam(source: string, filePath: string): seq[SecNode] =
  var taintedVars = initHashSet[string]()

  for lineNum in 0..<source.splitLines().len:
    let line = source.splitLines()[lineNum]
    let s = line.strip()
    if s.startsWith("//") or s.len == 0: continue

    # ── Function definitions: [pub] fn name(args) ────────────────
    let fnIdx = s.find("fn ")
    if fnIdx >= 0:
      var i = fnIdx + 3
      # skip spaces
      while i < s.len and s[i] == ' ': i.inc
      if i < s.len and s[i] in IdentStart:
        let (fname, afterName) = extractCallName(s, i)
        i = afterName
        # skip to (
        while i < s.len and s[i] == ' ': i.inc
        if i < s.len and s[i] == '(':
          let (fargs, closePos) = extractBalanced(s, i)
          result.add SecNode(
            typ: "def", name: fname,
            args: parseArgs(fargs),
            line: lineNum + 1, taint: false, file: filePath)

    # ── Let bindings: let [assert] name = rhs ────────────────────
    let letIdx = s.find("let ")
    if letIdx >= 0:
      var i = letIdx + 4
      while i < s.len and s[i] == ' ': i.inc
      # skip "assert"
      if s[i..min(i+5, s.high)] == "assert":
        i += 6
        while i < s.len and s[i] == ' ': i.inc
      if i < s.len and s[i] in IdentStart:
        let (target, afterTarget) = extractCallName(s, i)
        i = afterTarget
        while i < s.len and s[i] == ' ': i.inc
        if i < s.len and s[i] == '=':
          i.inc
          while i < s.len and s[i] == ' ': i.inc
          let rhs = s[i..^1]
          var taint = false
          for src in TaintSources:
            if rhs.contains(src): taint = true
          if not taint:
            for v in taintedVars:
              if rhs.contains(v): taint = true
          if taint: taintedVars.incl(target)
          let firstToken = rhs.split({'(', ' ', '{', '|', '>'})[0]
          result.add SecNode(
            typ: "assign", name: target,
            args: @[classifyArg(firstToken)],
            line: lineNum + 1, taint: taint, file: filePath)

    # ── Function calls: name(args) or module.name(args) ──────────
    var i = 0
    while i < s.len:
      if s[i] in IdentStart:
        let (callName, afterName) = extractCallName(s, i)
        i = afterName
        # skip spaces
        while i < s.len and s[i] == ' ': i.inc
        if i < s.len and s[i] == '(' and callName != "fn":
          let (callArgs, closePos) = extractBalanced(s, i)
          i = closePos + 1
          if SkipCalls.contains(callName): continue

          let args = parseArgs(callArgs)
          var taint = false
          for a in args:
            if a.argType == "var":
              if TaintSources.contains(a.value) or taintedVars.contains(a.value):
                taint = true
            if a.argType == "call" and a.value.contains("<interpolation>"):
              taint = true

          result.add SecNode(
            typ: "call", name: callName,
            args: args,
            line: lineNum + 1, taint: taint, file: filePath)
        else:
          discard # not a call, continue
      else:
        i.inc

# ── JSON output ────────────────────────────────────────────────────────

proc toJson(nodes: seq[SecNode]): JsonNode =
  var jnodes = newJArray()
  for n in nodes:
    var jargs = newJArray()
    for a in n.args:
      jargs.add(%*{"arg_type": a.argType, "value": a.value})
    jnodes.add(%*{
      "type": n.typ,
      "name": n.name,
      "args": jargs,
      "line": n.line,
      "taint": n.taint,
      "file": n.file,
    })
  return jnodes

# ── Main ───────────────────────────────────────────────────────────────

when isMainModule:
  if paramCount() < 1:
    stderr.writeLine "Usage: nim c -r gleam_extractor.nim <file.gleam>"
    quit(1)

  let filePath = paramStr(1)
  if not fileExists(filePath):
    stderr.writeLine &"Error: file not found: {filePath}"
    quit(1)

  let source = readFile(filePath)
  let nodes = extractGleam(source, filePath)
  echo nodes.toJson().pretty()
