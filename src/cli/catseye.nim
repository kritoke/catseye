## Catseye CLI — Nim Orchestrator
##
## Recursively discovers .cr files, runs the Crystal Extractor on each,
## sends the aggregated JSON to the Gleam/Erlang logic engine, and
## formats findings with colored terminal output.
##
## Usage: catseye <directory>

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
  Config = object
    targetDir: string
    extractorPath: string
    engineDir: string
    color: bool

# ── Styled output helper (DRY) ─────────────────────────────────────────

proc echoStyled(config: Config, codes: string, text: string) =
  ## Print text with ANSI codes if color is enabled.
  if config.color:
    echo &"{codes}{text}{Reset}"
  else:
    echo text

proc echoPlain(config: Config, text: string) =
  echo text

proc echoInfo(config: Config, text: string)    = config.echoStyled(Cyan, text)
proc echoSuccess(config: Config, text: string) = config.echoStyled(Green, text)
proc echoWarn(config: Config, text: string)    = config.echoStyled(Yellow, text)
proc echoError(config: Config, text: string)   = config.echoStyled(Red, text)

proc echoBold(config: Config, codes: string, text: string) =
  if config.color:
    echo &"{Bold}{codes}{text}{Reset}"
  else:
    echo text

# ── Core logic ─────────────────────────────────────────────────────────

proc findCrFiles(dir: string): seq[string] =
  for path in walkDirRec(dir):
    if path.endsWith(".cr"):
      result.add(path)
  result.sort()

proc runExtractor(extractor: string, filePath: string): (string, int) =
  let cmd = fmt"CRYSTAL_HAS_WRAPPER=1 crystal run {extractor} -- {filePath}"
  let (output, exitCode) = execCmdEx(cmd, options = {poStdErrToStdOut})
  return (output.strip(), exitCode)

proc runEngine(engineDir: string, jsonData: string): (string, int) =
  let beamPath = fmt"{engineDir}/build/dev/erlang/catseye_engine"
  let escaped = jsonData.replace("'", "'\\''")
  let cmd = fmt"echo '{escaped}' | erl -noshell -pa {beamPath}/ebin -pa {beamPath}/../gleam_stdlib/ebin -eval 'catseye:main(), erlang:halt()'"
  let (output, exitCode) = execCmdEx(cmd)
  return (output.strip(), exitCode)

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

proc printBanner(config: Config, fileCount: int) =
  config.echoBold(Cyan, "╔══════════════════════════════════════╗")
  config.echoBold(Cyan, "║          🔮 Catseye v0.1.0           ║")
  config.echoBold(Cyan, "╚══════════════════════════════════════╝")
  config.echoStyled(Green, &"  Target:   {config.targetDir}")
  config.echoPlain(&"  Files:    {fileCount} Crystal source(s)")
  config.echoPlain(&"  Engine:   Gleam/BEAM")
  echo ""

# ── Arg parsing ────────────────────────────────────────────────────────

proc parseArgs(): Config =
  var config = Config(
    extractorPath: "src/extractor/extractor.cr",
    engineDir: "src/engine",
    color: true,
    targetDir: "",
  )
  var p = initOptParser(commandLineParams())
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "extractor":  config.extractorPath = p.val
      of "engine":     config.engineDir = p.val
      of "no-color":   config.color = false
      of "color":      config.color = true
      of "help", "h":
        echo "Usage: catseye [options] <directory>"
        echo ""
        echo "Options:"
        echo "  --extractor <path>   Crystal extractor path"
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

  # Step 1: Discover
  let files = findCrFiles(config.targetDir)
  if files.len == 0:
    echo &"No .cr files found in {config.targetDir}"
    quit(0)

  printBanner(config, files.len)

  # Step 2: Extract
  var allNodes = newJArray()
  for filePath in files:
    config.echoInfo(&"→ Extracting: {filePath}")
    let (output, exitCode) = runExtractor(config.extractorPath, filePath)
    if exitCode != 0:
      config.echoWarn(&"  ⚠ Extractor failed (exit {exitCode})")
      continue
    if output.len > 0:
      try:
        let nodes = parseJson(output)
        if nodes.kind == JArray:
          for n in nodes:
            allNodes.add(n)
      except JsonParsingError:
        config.echoWarn("  ⚠ Invalid JSON from extractor")

  echo ""

  if allNodes.len == 0:
    config.echoWarn("No AST nodes extracted. Nothing to analyze.")
    quit(0)

  # Step 3: Analyze
  config.echoInfo(&"→ Running analysis engine ({allNodes.len} nodes)...")
  let (engineOutput, engineExit) = runEngine(config.engineDir, $allNodes)
  if engineExit != 0:
    config.echoError(&"✗ Engine failed (exit {engineExit})")
    echo &"  Output: {engineOutput[0..min(200, engineOutput.len-1)]}"
    quit(1)

  # Step 4: Report
  echo ""
  var findingsCount = 0
  if engineOutput.len > 0:
    try:
      let findings = parseJson(engineOutput)
      if findings.kind == JArray:
        findingsCount = findings.len
        for f in findings:
          printFinding(config, f)
    except JsonParsingError:
      config.echoWarn("⚠ Invalid JSON from engine")
      echo &"  Raw: {engineOutput[0..min(200, engineOutput.len-1)]}"

  echo "─────────────────────────────────────────"
  if findingsCount > 0:
    config.echoError(&"Found {findingsCount} issue(s) across {files.len} file(s).")
    quit(1)
  else:
    config.echoSuccess(&"No issues found across {files.len} file(s). ✨")

when isMainModule:
  main()
