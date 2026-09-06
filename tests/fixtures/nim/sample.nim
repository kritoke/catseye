# Sample Nim file for catseye testing
# Covers: procs, pragmas, taint paths, imports, types, case/of, try/except, UFCS

import os
import osproc
import strutils
import httpclient
import json
import net
import streams

# Type declarations
type
  User = object
    name: string
    age: int
    email: string

  Color = enum
    Red, Green, Blue

  Result[T] = object
    case success: bool
    of true:
      value: T
    of false:
      error: string

# Const/let/var declarations
const
  MaxRetries = 3
  DefaultPort = 8080

let
  appName = "catseye-test"
  version = "1.0.0"

var
  globalCounter = 0
  connectionPool: seq[net.Socket]

# Safe procedures
proc greet(name: string): string =
  ## Greet a user by name
  result = "Hello, " & name & "!"

proc add(a, b: int): int {.noSideEffect.} =
  return a + b

# Taint source → sink: command injection via execCmd
proc runUserCommand(userInput: string) =
  let cmd = "echo " & userInput  # Tainted!
  let exitCode = os.execCmd(cmd)  # Sink: command injection
  echo "Exit code: ", exitCode

# Taint source → sink: command injection via execShellCmd
proc dangerousExec() =
  let param = os.getEnv("USER_INPUT")  # Source
  discard os.execShellCmd("ls " & param)  # Sink

# Taint source → sink: path traversal
proc readUserFile(filename: string) =
  let content = readFile(filename)  # Sink: path traversal
  echo content

# Taint source → sink: SSRF
proc fetchUserUrl(url: string) =
  let client = newHttpClient()
  let response = client.getContent(url)  # Sink: SSRF
  echo response

# UFCS calls
proc processUser(u: User): string =
  let upperName = u.name.toUpperAscii()  # UFCS: toUpperAscii(u.name)
  let stripped = upperName.strip()        # UFCS: strip(upperName)
  return stripped

# Case statement
proc describeColor(c: Color): string =
  case c
  of Red:
    return "red"
  of Green:
    return "green"
  of Blue:
    return "blue"

# Try/except with bare except (antipattern)
proc riskyOperation() =
  try:
    let data = readFile("config.json")
    let parsed = parseJson(data)
    echo parsed
  except:
    echo "Something went wrong"  # bare except — antipattern

# Try/except with specific exception (good)
proc safeOperation() =
  try:
    let data = readFile("config.json")
    echo data
  except IOError as e:
    echo "IO error: ", e.msg
  except JsonParsingError:
    echo "Invalid JSON"

# If/elif/else
proc classify(x: int): string =
  if x < 0:
    return "negative"
  elif x == 0:
    return "zero"
  else:
    return "positive"

# For loop
proc sumArray(arr: seq[int]): int =
  var total = 0
  for item in arr:
    total += item
  return total

# Network operation without timeout (antipattern)
proc connectToServer(host: string, port: int) =
  var socket = newSocket()
  socket.connect(host, Port(port))
  let data = socket.recv(1024)  # No timeout
  echo data
  socket.close()

# SQL injection risk
import db_sqlite
proc getUser(db: DbConn, userId: string): string =
  let query = "SELECT name FROM users WHERE id = '" & userId & "'"
  return db.getValue(query)  # Sink: SQL injection

# JSON deserialization from untrusted input
proc loadConfig(data: string): User =
  let parsed = parseJson(data)
  return parsed.to(User)  # Deserialization

# Proc with pragmas
proc importantProc() {.raises: [IOError], tags: [ReadIOEffect].} =
  let data = readFile("important.txt")
  echo data

# Iterator
iterator countdown(n: int): int =
  var i = n
  while i > 0:
    yield i
    dec i

# Template
template withDir(dir: string, body: untyped) =
  let oldDir = getCurrentDir()
  setCurrentDir(dir)
  try:
    body
  finally:
    setCurrentDir(oldDir)

# Generic proc
proc find[T](arr: seq[T], target: T): int =
  for i, item in arr:
    if item == target:
      return i
  return -1

# Long procedure (for complexity detection)
proc complexLogic(input: seq[int]): seq[int] =
  var output: seq[int] = @[]
  for x in input:
    if x > 0:
      if x mod 2 == 0:
        if x < 100:
          output.add(x * 2)
        else:
          output.add(x + 10)
      else:
        if x < 50:
          output.add(x * 3)
        else:
          output.add(x - 5)
    elif x == 0:
      output.add(0)
    else:
      if x > -100:
        output.add(abs(x))
      else:
        output.add(0)
  return output

# Main
when isMainModule:
  echo greet("World")
  echo add(2, 3)
  runUserCommand("test")
  echo describeColor(Red)
  echo classify(5)
