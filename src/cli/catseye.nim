## Catseye CLI — Nim Orchestrator
##
## Recursively discovers .cr and .gleam files, runs the appropriate
## extractor, sends aggregated JSON to the Gleam/Erlang logic engine,
## and formats findings with colored terminal output, JSON, or SARIF.
##
## Usage: catseye [options] <directory>
##   --format json    Machine-readable JSON
##   --format sarif   SARIF v2.1.0 (GitHub Code Scanning compatible)
##   --no-color       Disable colored output

import std/[os, osproc, strutils, json, parseopt, strformat, algorithm, sets]

const
  Bold   = "\e[1m"
  Dim    = "\e[2m"
  Red    = "\e[31m"
  Yellow = "\e[33m"
  Green  = "\e[32m"
  Cyan   = "\e[36m"
  Reset  = "\e[0m"

type
  OutputFormat = enum fmtTerminal, fmtJson, fmtSarif
  Config = object
    targetDir: string
    crystalExtractor: string
    gleamExtractor: string
    engineDir: string
    color: bool
    format: OutputFormat

# ── Styled output helpers ──────────────────────────────────────────────

proc echoStyled(config: Config, codes: string, text: string) =
  if config.color: echo &"{codes}{text}{Reset}"
  else: echo text

proc echoPlain(config: Config, text: string)    = echo text
proc echoInfo(config: Config, text: string)     = config.echoStyled(Cyan, text)
proc echoSuccess(config: Config, text: string)  = config.echoStyled(Green, text)
proc echoWarn(config: Config, text: string)     = config.echoStyled(Yellow, text)
proc echoError(config: Config, text: string)    = config.echoStyled(Red, text)

proc echoBold(config: Config, codes: string, text: string) =
  if config.color: echo &"{Bold}{codes}{text}{Reset}"
  else: echo text

# ── File discovery ─────────────────────────────────────────────────────

type SourceFile = object
  path: string
  lang: string

proc discoverSources(dir: string): seq[SourceFile] =
  for path in walkDirRec(dir):
    if path.endsWith(".cr"):
      result.add SourceFile(path: path, lang: "crystal")
    elif path.endsWith(".gleam"):
      result.add SourceFile(path: path, lang: "gleam")
  result.sort(proc(a, b: SourceFile): int = cmp(a.path, b.path))

# ── Extractors ─────────────────────────────────────────────────────────

proc getGleamGrammar(): string =
  result = getEnv("TREE_SITTER_GLEAM_GRAMMAR")
  if result.len == 0:
    stderr.writeLine "Error: TREE_SITTER_GLEAM_GRAMMAR not set. Run in nix develop."
    quit(1)

proc runCrystalExtractor(extractor: string, filePath: string): (string, int) =
  let cmd = fmt"CRYSTAL_HAS_WRAPPER=1 crystal run {extractor} -- {filePath} 2>/dev/null"
  execCmdEx(cmd)

proc runGleamExtractor(extractor: string, filePath: string): (string, int) =
  let grammar = getGleamGrammar()
  let cmd = fmt"{extractor} {filePath} 2>/dev/null"
  execCmdEx(cmd)

# ── Engine ─────────────────────────────────────────────────────────────

proc runEngine(engineDir: string, jsonData: string): (string, int) =
  let beamPath = fmt"{engineDir}/build/dev/erlang/catseye_engine"
  let tmpFile = "/tmp/catseye-engine-input.json"
  writeFile(tmpFile, jsonData)
  let cmd = fmt"cat {tmpFile} | erl -noshell -pa {beamPath}/ebin -pa {beamPath}/../gleam_stdlib/ebin -eval 'catseye:main(), erlang:halt()' 2>/dev/null"
  let (output, exitCode) = execCmdEx(cmd)
  removeFile(tmpFile)
  return (output.strip(), exitCode)

# ── Terminal formatting ────────────────────────────────────────────────

proc severityColor(sev: string): string =
  case sev.toLowerAscii()
  of "critical", "high": Red
  of "medium":           Yellow
  of "low", "info":      Cyan
  else:                  Cyan

proc printFinding(config: Config, finding: JsonNode) =
  let rule     = finding["rule"].getStr()
  let severity = finding["severity"].getStr()
  let file     = finding["file"].getStr()
  let line     = finding["line"].getInt()
  let message  = finding["message"].getStr()
  let c = severityColor(severity)
  config.echoBold(c, &"[{rule}] {severity}  {file}:{line}")
  config.echoStyled(Dim, &"  {message}")
  echo ""

proc printBanner(config: Config, crCount, gleamCount: int) =
  config.echoBold(Cyan, "╔══════════════════════════════════════╗")
  config.echoBold(Cyan, "║          🔮 Catseye v0.1.0           ║")
  config.echoBold(Cyan, "╚══════════════════════════════════════╝")
  config.echoStyled(Green, &"  Target:   {config.targetDir}")
  config.echoPlain(&"  Files:    {crCount} Crystal, {gleamCount} Gleam")
  config.echoPlain(&"  Engine:   Gleam/BEAM")
  echo ""

# ── SARIF v2.1.0 output ───────────────────────────────────────────────

proc severityToSarifLevel(sev: string): string =
  case sev.toLowerAscii()
  of "critical": "error"
  of "high":     "error"
  of "medium":   "warning"
  of "low":      "note"
  of "info":     "note"
  else:          "warning"

proc buildSarifRules(findings: JsonNode): seq[JsonNode] =
  var seen = initHashSet[string]()
  for f in findings:
    let rule = f["rule"].getStr()
    if not seen.contains(rule):
      seen.incl(rule)
      let sev = f["severity"].getStr()
      result.add(%*{
        "id": rule,
        "shortDescription": {"text": fmt"Potential {rule} vulnerability detected"},
        "fullDescription": {"text": fmt"Catseye detected a potential {rule} vulnerability. Review the flagged code for security implications."},
        "defaultConfiguration": {"level": severityToSarifLevel(sev)},
        "properties": {
          "tags": ["security", fmt"vulnerability/{rule.toLowerAscii()}"],
          "precision": "medium",
        },
      })

proc toRelativeUri(file, targetDir: string): string =
  result = file
  if result.startsWith(targetDir):
    result = result[targetDir.len .. ^1]
    if result.startsWith("/"): result = result[1 .. ^1]

proc buildSarifResults(findings: JsonNode, rules: seq[JsonNode], targetDir: string): seq[JsonNode] =
  for f in findings:
    let rule     = f["rule"].getStr()
    let severity = f["severity"].getStr()
    let file     = f["file"].getStr()
    let line     = f["line"].getInt()
    let message  = f["message"].getStr()
    let uri = toRelativeUri(file, targetDir)
    var ruleIdx = 0
    for j, r in rules:
      if r["id"].getStr() == rule:
        ruleIdx = j
        break
    result.add(%*{
      "ruleId": rule,
      "ruleIndex": ruleIdx,
      "level": severityToSarifLevel(severity),
      "message": {"text": message},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": uri},
          "region": {"startLine": line},
        },
      }],
    })

proc toSarif(findings: JsonNode, targetDir: string): JsonNode =
  let rules = buildSarifRules(findings)
  let results = buildSarifResults(findings, rules, targetDir)
  return %*{
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
      "tool": {
        "driver": {
          "name": "Catseye",
          "version": "0.1.0",
          "semanticVersion": "0.1.0",
          "informationUri": "https://github.com/kritoke/catseye",
          "rules": rules,
        },
      },
      "results": results,
      "invocations": [{
        "executionSuccessful": true,
        "toolExecutionNotifications": [],
      }],
    }],
  }

# ── Arg parsing ────────────────────────────────────────────────────────

proc parseArgs(): Config =
  var config = Config(
    crystalExtractor: "src/extractor/extractor.cr",
    gleamExtractor: "bin/gleam_extractor",
    engineDir: "src/engine",
    color: true,
    format: fmtTerminal,
    targetDir: "",
  )
  var p = initOptParser(commandLineParams())
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "crystal-extractor": config.crystalExtractor = p.val
      of "gleam-extractor":   config.gleamExtractor = p.val
      of "engine":            config.engineDir = p.val
      of "no-color":          config.color = false
      of "color":             config.color = true
      of "format":
        var fmtVal = p.val
        if fmtVal.len == 0:
          p.next()
          fmtVal = p.key
        case fmtVal.toLowerAscii()
        of "json":            config.format = fmtJson
        of "sarif":           config.format = fmtSarif
        of "terminal", "text": config.format = fmtTerminal
        else:
          echo &"Unknown format: {fmtVal} (use: json, sarif, terminal)"
          quit(1)
      of "help", "h":
        echo "Usage: catseye [options] <directory>"
        echo ""
        echo "Options:"
        echo "  --format <fmt>       Output format: terminal (default), json, sarif"
        echo "  --crystal-extractor  Crystal extractor path"
        echo "  --gleam-extractor    Gleam extractor binary path"
        echo "  --engine <path>      Gleam engine directory"
        echo "  --no-color           Disable colored output"
        echo "  -h, --help           Show this help"
        quit(0)
      else:
        echo &"Unknown option: {p.key}"
        quit(1)
    of cmdArgument:
      if config.targetDir == "":
        config.targetDir = p.key
      else:
        echo &"Unexpected argument: {p.key}"
        quit(1)

  if config.targetDir == "":
    echo "Error: no target directory specified."
    echo "Usage: catseye <directory>"
    quit(1)

  if not dirExists(config.targetDir):
    echo &"Error: directory not found: {config.targetDir}"
    quit(1)

  return config

# ── Main ───────────────────────────────────────────────────────────────

proc main() =
  let config = parseArgs()

  # Step 1: Discover sources
  let sources = discoverSources(config.targetDir)
  if sources.len == 0:
    echo &"No .cr or .gleam files found in {config.targetDir}"
    quit(0)

  var crCount = 0
  var gleamCount = 0
  for s in sources:
    if s.lang == "crystal": crCount.inc()
    elif s.lang == "gleam": gleamCount.inc()

  if config.format == fmtTerminal:
    printBanner(config, crCount, gleamCount)

  # Step 2: Extract
  var allNodes = newJArray()
  for src in sources:
    if config.format == fmtTerminal:
      config.echoInfo(&"→ Extracting: {src.path}")
    let (output, exitCode) =
      case src.lang
      of "crystal":
        runCrystalExtractor(config.crystalExtractor, src.path)
      of "gleam":
        runGleamExtractor(config.gleamExtractor, src.path)
      else: ("", 1)
    if exitCode != 0:
      if config.format == fmtTerminal:
        config.echoWarn(&"  ⚠ Extractor failed (exit {exitCode})")
      continue
    if output.len > 0:
      try:
        let nodes = parseJson(output)
        if nodes.kind == JArray:
          for n in nodes: allNodes.add(n)
      except JsonParsingError:
        if config.format == fmtTerminal:
          config.echoWarn(&"  ⚠ Invalid JSON from extractor: {src.path}")

  if allNodes.len == 0:
    if config.format == fmtTerminal:
      echo ""
      config.echoWarn("No AST nodes extracted. Nothing to analyze.")
    quit(0)

  # Step 3: Analyze
  if config.format == fmtTerminal:
    echo ""
    config.echoInfo(&"→ Running analysis engine ({allNodes.len} nodes)...")
    echo ""

  let (engineOutput, engineExit) = runEngine(config.engineDir, $allNodes)
  if engineExit != 0:
    if config.format == fmtTerminal:
      config.echoError(&"✗ Engine failed (exit {engineExit})")
    quit(1)

  # Step 4: Report
  var findingsCount = 0
  var findings = newJArray()
  if engineOutput.len > 0:
    try:
      findings = parseJson(engineOutput)
      if findings.kind == JArray:
        findingsCount = findings.len
    except JsonParsingError:
      if config.format == fmtTerminal:
        config.echoWarn("⚠ Invalid JSON from engine")

  # Output based on format
  case config.format
  of fmtJson:
    var output = %*{
      "version": "0.1.0",
      "target": config.targetDir,
      "files_scanned": sources.len,
      "nodes_extracted": allNodes.len,
      "findings_count": findingsCount,
      "findings": findings,
    }
    echo output.pretty()
  of fmtSarif:
    echo toSarif(findings, config.targetDir).pretty()
  of fmtTerminal:
    for f in findings:
      printFinding(config, f)
    echo "─────────────────────────────────────────"
    if findingsCount > 0:
      config.echoError(&"Found {findingsCount} issue(s) across {sources.len} file(s).")
      quit(1)
    else:
      config.echoSuccess(&"No issues found across {sources.len} file(s). ✨")

when isMainModule:
  main()
