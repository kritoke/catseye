## Catseye Gleam Extractor — Nim + tree-sitter
##
## Parses .gleam files using tree-sitter with the Gleam grammar,
## then walks the XML CST to extract Security Node JSON.
##
## Usage: nim c -r src/extractor/gleam_extractor.nim <file.gleam>
## Env:   TREE_SITTER_GLEAM_GRAMMAR=path/to/parser.so

import std/[os, json, strformat, sets, xmltree, xmlparser, streams,
            osproc, algorithm, strutils]

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
  "request.get_body",
])

const SkipCalls = toHashSet([
  "list.map", "list.filter", "list.each", "list.any", "list.fold",
  "list.append", "list.length", "list.reverse",
  "result.try", "result.map", "result.then", "result.is_ok",
  "result.is_err", "result.unwrap",
  "option.map", "option.unwrap", "option.is_some",
  "io.println", "io.print", "io.debug",
  "string.concat", "string.join", "string.slice", "string.split",
  "string.starts_with", "string.ends_with", "string.contains",
  "string.replace", "string.lowercase", "string.uppercase",
  "int.to_string", "int.parse", "float.to_string",
  "dict.new", "dict.insert", "dict.get", "dict.values",
  "tuple.first", "tuple.second",
])

# ── tree-sitter invocation ──────────────────────────────────────────────

proc getGrammarPath(): string =
  result = getEnv("TREE_SITTER_GLEAM_GRAMMAR")
  if result.len == 0:
    stderr.writeLine "Error: TREE_SITTER_GLEAM_GRAMMAR not set. Run in nix develop."
    quit(1)

proc parseWithTreeSitter(filePath: string): XmlNode =
  let grammar = getGrammarPath()
  let cmd = fmt"tree-sitter parse --lib-path '{grammar}' --lang-name gleam -x '{filePath}' 2>/dev/null"
  let (output, exitCode) = execCmdEx(cmd)
  if exitCode != 0:
    stderr.writeLine &"tree-sitter failed (exit {exitCode})"
    quit(1)
  parseXml(newStringStream(output))

# ── Safe XML helpers ────────────────────────────────────────────────────
## Nim's xmltree procs like tag() and attr() assert on non-element nodes.
## We wrap everything to be safe.

proc st(n: XmlNode): string =
  ## Safe tag name — returns "" for text nodes
  if n.kind == xnElement: n.tag() else: ""

proc sa(n: XmlNode, name: string): string =
  ## Safe attribute — returns "" for text nodes or missing attrs
  if n.kind != xnElement: return ""
  try:
    let a = n.attr(name)
    if a.len == 0: ""
    else: a
  except:
    ""

proc ln(n: XmlNode): int =
  ## Line number from srow attr (0-indexed → 1-indexed)
  let s = n.sa("srow")
  if s.len > 0: parseInt(s) + 1 else: 0

proc txt(n: XmlNode): string =
  ## Direct text content only (not recursive)
  result = ""
  for c in n.items:
    if c.kind == xnText: result.add(c.text)

proc elChildren(n: XmlNode): seq[XmlNode] =
  ## Return only element children (skip text nodes)
  for c in n.items:
    if c.kind == xnElement: result.add(c)

# ── Arg extraction ──────────────────────────────────────────────────────

proc classifyArg(node: XmlNode): ArgNode =
  let t = node.st()
  case t
  of "string":
    let qc = node.findAll("quoted_content")
    if qc.len > 0:
      ArgNode(argType: "literal", value: qc[0].txt().strip())
    else:
      ArgNode(argType: "literal", value: "")
  of "integer":
    ArgNode(argType: "literal", value: node.txt().strip())
  of "float":
    ArgNode(argType: "literal", value: node.txt().strip())
  of "identifier":
    ArgNode(argType: "var", value: node.txt().strip())
  of "field_access":
    var parts: seq[string]
    for p in node.findAll("identifier"):
      parts.add(p.txt().strip())
    for l in node.findAll("label"):
      parts.add(l.txt().strip())
    ArgNode(argType: "call", value: parts.join("."))
  else:
    ArgNode(argType: "unknown", value: t)

proc extractArgs(callNode: XmlNode): seq[ArgNode] =
  let argsContainers = callNode.findAll("arguments")
  if argsContainers.len == 0: return @[]
  for child in argsContainers[0].elChildren():
    if child.st() == "argument":
      for vc in child.elChildren():
        let vt = vc.st()
        if vt in ["string", "integer", "float", "identifier", "field_access", "tuple", "record"]:
          result.add(classifyArg(vc))

# ── Call name ───────────────────────────────────────────────────────────

proc extractCallName(callNode: XmlNode): string =
  # The function being called is the first element child with field="function"
  for child in callNode.elChildren():
    let ct = child.st()
    let fieldAttr = child.sa("field")
    if fieldAttr != "function": continue
    case ct
    of "identifier":
      return child.txt().strip()
    of "field_access":
      var parts: seq[string]
      for p in child.findAll("identifier"):
        parts.add(p.txt().strip())
      for l in child.findAll("label"):
        parts.add(l.txt().strip())
      return parts.join(".")
    of "label":
      return child.txt().strip()
    else: discard
  return ""

# ── Extraction ──────────────────────────────────────────────────────────

proc extractNodes(root: XmlNode, filePath: string): seq[SecNode] =
  var taintedVars = initHashSet[string]()
  var allNodes: seq[SecNode]

  # ── Function definitions ─────────────────────────────────────────
  for fn in root.findAll("function"):
    var fname = ""
    for n in fn.findAll("identifier"):
      if n.sa("field") == "name":
        fname = n.txt().strip()
        break
    if fname.len == 0: continue

    var args: seq[ArgNode]
    for p in fn.findAll("function_parameter"):
      for child in p.elChildren():
        if child.st() == "identifier" and child.sa("field") == "name":
          args.add(ArgNode(argType: "var", value: child.txt().strip()))

    allNodes.add SecNode(
      typ: "def", name: fname, args: args,
      line: fn.ln(), taint: false, file: filePath)

  # ── Let bindings (let + let_assert) ──────────────────────────────
  for tagName in ["let", "let_assert"]:
    for lt in root.findAll(tagName):
      var target = ""
      var rhsValue = ""
      var rhsType = "unknown"
      for child in lt.elChildren():
        if child.sa("field") == "pattern" and child.st() == "identifier":
          target = child.txt().strip()
        if child.sa("field") == "value":
          for vc in child.elChildren():
            let vt = vc.st()
            if vt in ["string", "integer", "float", "identifier",
                      "field_access", "function_call"]:
              let arg = classifyArg(vc)
              rhsValue = arg.value
              rhsType = arg.argType
              break

      if target.len == 0: continue

      var taint = false
      let fullRhs = $lt
      for src in TaintSources:
        if fullRhs.contains(src): taint = true
      if not taint:
        for v in taintedVars:
          if fullRhs.contains(v): taint = true
      if taint: taintedVars.incl(target)

      allNodes.add SecNode(
        typ: "assign", name: target,
        args: if rhsValue.len > 0: @[ArgNode(argType: rhsType, value: rhsValue)] else: @[],
        line: lt.ln(), taint: taint, file: filePath)

  # ── Function calls ───────────────────────────────────────────────
  for call in root.findAll("function_call"):
    let callName = extractCallName(call)
    if callName.len == 0 or callName == "fn": continue
    if SkipCalls.contains(callName): continue

    let args = extractArgs(call)
    var taint = false
    for a in args:
      if a.argType == "var":
        if TaintSources.contains(a.value) or taintedVars.contains(a.value):
          taint = true
      if a.argType == "call" and a.value.contains("<interpolation>"):
        taint = true

    allNodes.add SecNode(
      typ: "call", name: callName, args: args,
      line: call.ln(), taint: taint, file: filePath)

  allNodes.sort(proc(a, b: SecNode): int = cmp(a.line, b.line))
  return allNodes

# ── JSON output ─────────────────────────────────────────────────────────

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

# ── Main ─────────────────────────────────────────────────────────────────

when isMainModule:
  if paramCount() < 1:
    stderr.writeLine "Usage: nim c -r gleam_extractor.nim <file.gleam>"
    quit(1)
  let filePath = paramStr(1)
  if not fileExists(filePath):
    stderr.writeLine &"Error: file not found: {filePath}"
    quit(1)
  let xmlRoot = parseWithTreeSitter(filePath)
  let nodes = extractNodes(xmlRoot, filePath)
  echo nodes.toJson().pretty()
