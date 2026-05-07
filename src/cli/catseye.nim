## Catseye CLI — Nim Orchestrator
##
## Recursively discovers .cr and .gleam files, runs the appropriate
## extractor, sends aggregated JSON to the Gleam/Erlang logic engine,
## and formats findings with colored terminal output or JSON.
##
## Usage: catseye [options] <directory>
##   --format json    Machine-readable JSON output (for CI)
##   --no-color       Disable colored output
##   --format-only    Only run extractor, skip engine (debug)

import std/[os, osproc, strutils, json, parseopt, strformat, algorithm]

const
  Bold   = "\e[1m"
  Dim    = "\e[2m"
  Red    = "\e[31m"
  Yellow = "\e[33m"
  Green  = "\e[32m"
  Cyan   = "\e[36m"
  Reset  = "\e[0m"

type
  OutputFormat = enum fmtTerminal, fmtJson
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
  lang: string  # "crystal" or "gleam"

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

# ── Formatting ─────────────────────────────────────────────────────────

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
        of "json": config.format = fmtJson
        of "terminal", "text": config.format = fmtTerminal
        else:
          echo &"Unknown format: {p.val} (use: json, terminal)"
          quit(1)
      of "help", "h":
        echo "Usage: catseye [options] <directory>"
        echo ""
        echo "Options:"
        echo "  --format <fmt>       Output format: terminal (default), json"
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

  # JSON output mode
  if config.format == fmtJson:
    var output = %*{
      "version": "0.1.0",
      "target": config.targetDir,
      "files_scanned": sources.len,
      "nodes_extracted": allNodes.len,
      "findings_count": findingsCount,
      "findings": findings,
    }
    echo output.pretty()
  else:
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
