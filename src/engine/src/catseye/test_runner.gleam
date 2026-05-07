import catseye/node.{
  type Arg, type Node, Arg, ArgCall, ArgLiteral, ArgVar, Assign, Call, Def, Node,
}
import catseye/rules
import catseye/rules/command_injection
import catseye/rules/path_traversal
import catseye/rules/sql_injection
import catseye/rules/ssrf
import catseye/rules/taint
import gleam/int
import gleam/io
import gleam/list

fn node_(
  type_: node.NodeType,
  name: String,
  args: List(Arg),
  taint: Bool,
) -> Node {
  Node(
    node_type: type_,
    name: name,
    args: args,
    line: 1,
    taint: taint,
    file: "test.cr",
  )
}

fn arg_(type_: node.ArgType, value: String) -> Arg {
  Arg(arg_type: type_, value: value)
}

fn assert_eq(label: String, got: a, want: a) -> Bool {
  case got == want {
    True -> True
    False -> {
      io.println("  FAIL: " <> label)
      False
    }
  }
}

fn make_db(nodes: List(Node)) -> taint.TaintDB {
  taint.build_taint_db(nodes)
}

fn tv(nodes: List(Node)) -> List(String) {
  taint.tainted_vars_list(make_db(nodes))
}

// -- Taint --
fn taint_extracts() -> Bool {
  let nodes = [
    node_(Assign, "x", [arg_(ArgVar, "params")], True),
    node_(Assign, "y", [arg_(ArgLiteral, "safe")], False),
  ]
  let tainted = taint.build_tainted_vars(nodes)
  assert_eq("tainted count", list.length(tainted), 1)
  && assert_eq("has x", list.contains(tainted, "x"), True)
}

fn taint_propagates() -> Bool {
  let nodes = [
    node_(Assign, "a", [arg_(ArgVar, "params")], True),
    node_(Assign, "b", [arg_(ArgVar, "a")], False),
  ]
  assert_eq("b tainted", taint.is_tainted(make_db(nodes), "b"), True)
}

fn taint_multi_hop() -> Bool {
  let nodes = [
    node_(Assign, "a", [arg_(ArgVar, "request")], True),
    node_(Assign, "b", [arg_(ArgVar, "a")], False),
    node_(Assign, "c", [arg_(ArgVar, "b")], False),
  ]
  let db = make_db(nodes)
  assert_eq("c tainted", taint.is_tainted(db, "c"), True)
  && assert_eq("b tainted", taint.is_tainted(db, "b"), True)
}

fn taint_no_false() -> Bool {
  let nodes = [
    node_(Assign, "x", [arg_(ArgLiteral, "ok")], False),
    node_(Assign, "y", [arg_(ArgLiteral, "fine")], False),
  ]
  let db = make_db(nodes)
  assert_eq("x clean", taint.is_tainted(db, "x"), False)
  && assert_eq("y clean", taint.is_tainted(db, "y"), False)
}

fn taint_flow() -> Bool {
  let nodes = [
    node_(Assign, "src", [arg_(ArgVar, "request")], True),
    node_(Assign, "mid", [arg_(ArgVar, "src")], False),
  ]
  let flow = taint.trace_flow(make_db(nodes), "mid")
  assert_eq("flow steps", list.length(flow) >= 1, True)
}

// -- SSRF --
fn ssrf_var() -> Bool {
  let n = [node_(Call, "HTTP::Client.get", [arg_(ArgVar, "url")], False)]
  assert_eq("ssrf var", list.length(ssrf.check(n, tv(n), make_db(n))), 1)
}

fn ssrf_literal() -> Bool {
  let n = [
    node_(
      Call,
      "HTTP::Client.get",
      [arg_(ArgLiteral, "https://example.com")],
      False,
    ),
  ]
  assert_eq("ssrf literal", list.length(ssrf.check(n, tv(n), make_db(n))), 0)
}

fn ssrf_tainted() -> Bool {
  let n = [
    node_(Assign, "t", [arg_(ArgVar, "params")], True),
    node_(Call, "HTTP::Client.get", [arg_(ArgVar, "t")], False),
  ]
  assert_eq("ssrf tainted", list.length(ssrf.check(n, tv(n), make_db(n))), 1)
}

fn ssrf_all() -> Bool {
  let n =
    list.map(
      [
        "HTTP::Client.get",
        "HTTP::Client.post",
        "HTTP::Client.put",
        "HTTP::Client.delete",
      ],
      fn(m) { node_(Call, m, [arg_(ArgVar, "u")], False) },
    )
  assert_eq("ssrf all", list.length(ssrf.check(n, tv(n), make_db(n))), 4)
}

fn ssrf_non_http() -> Bool {
  let n = [node_(Call, "puts", [arg_(ArgVar, "d")], False)]
  assert_eq("ssrf non-http", list.length(ssrf.check(n, tv(n), make_db(n))), 0)
}

// -- Cmdi --
fn cmdi_system() -> Bool {
  let n = [node_(Call, "system", [arg_(ArgVar, "c")], False)]
  assert_eq(
    "cmdi system",
    list.length(command_injection.check(n, tv(n), make_db(n))),
    1,
  )
}

fn cmdi_os_cmd() -> Bool {
  let n = [node_(Call, "os.command", [arg_(ArgVar, "c")], False)]
  assert_eq(
    "cmdi os.command",
    list.length(command_injection.check(n, tv(n), make_db(n))),
    1,
  )
}

fn cmdi_literal() -> Bool {
  let n = [node_(Call, "system", [arg_(ArgLiteral, "echo")], False)]
  assert_eq(
    "cmdi literal",
    list.length(command_injection.check(n, tv(n), make_db(n))),
    0,
  )
}

fn cmdi_db() -> Bool {
  let n = [node_(Call, "db.exec", [arg_(ArgVar, "s")], False)]
  assert_eq(
    "cmdi db",
    list.length(command_injection.check(n, tv(n), make_db(n))),
    0,
  )
}

// -- PT --
fn pt_file() -> Bool {
  let n = [node_(Call, "File.read", [arg_(ArgVar, "p")], False)]
  assert_eq(
    "pt file",
    list.length(path_traversal.check(n, tv(n), make_db(n))),
    1,
  )
}

fn pt_literal() -> Bool {
  let n = [node_(Call, "File.read", [arg_(ArgLiteral, "ok")], False)]
  assert_eq(
    "pt literal",
    list.length(path_traversal.check(n, tv(n), make_db(n))),
    0,
  )
}

fn pt_interp() -> Bool {
  let n = [node_(Call, "Dir.glob", [arg_(ArgCall, "<interpolation>")], False)]
  assert_eq(
    "pt interp",
    list.length(path_traversal.check(n, tv(n), make_db(n))),
    1,
  )
}

// -- SQLi --
fn sqli_query() -> Bool {
  let n = [node_(Call, "DB.query", [arg_(ArgVar, "s")], False)]
  assert_eq(
    "sqli query",
    list.length(sql_injection.check(n, tv(n), make_db(n))),
    1,
  )
}

fn sqli_literal() -> Bool {
  let n = [node_(Call, "DB.query", [arg_(ArgLiteral, "SELECT 1")], False)]
  assert_eq(
    "sqli literal",
    list.length(sql_injection.check(n, tv(n), make_db(n))),
    0,
  )
}

// -- Integration --
fn all_rules() -> Bool {
  let n = [
    node_(Call, "HTTP::Client.get", [arg_(ArgVar, "u")], False),
    node_(Call, "system", [arg_(ArgVar, "c")], False),
    node_(Call, "File.read", [arg_(ArgVar, "p")], False),
    node_(Call, "DB.query", [arg_(ArgVar, "s")], False),
  ]
  assert_eq("all rules", list.length(rules.run_all_rules(n)), 4)
}

fn empty() -> Bool {
  assert_eq("empty", list.length(rules.run_all_rules([])), 0)
}

// -- Sanitizer --
fn sanitizer_uri() -> Bool {
  // URI.parse(x) should NOT be flagged as SSRF
  let n = [
    node_(Assign, "url", [arg_(ArgVar, "params")], True),
    node_(Call, "HTTP::Client.get", [arg_(ArgCall, "URI.parse")], False),
  ]
  assert_eq("sanitizer uri", list.length(ssrf.check(n, tv(n), make_db(n))), 0)
}

fn sanitizer_string() -> Bool {
  // String.strip(x) should NOT be flagged
  let n = [
    node_(Assign, "x", [arg_(ArgVar, "input")], True),
    node_(Call, "system", [arg_(ArgCall, "String.strip")], False),
  ]
  assert_eq(
    "sanitizer string",
    list.length(command_injection.check(n, tv(n), make_db(n))),
    0,
  )
}

fn sanitizer_path() -> Bool {
  // Path.basename(x) should NOT be flagged as path traversal
  let n = [
    node_(Assign, "p", [arg_(ArgVar, "input")], True),
    node_(Call, "File.read", [arg_(ArgCall, "Path.posix")], False),
  ]
  assert_eq(
    "sanitizer path",
    list.length(path_traversal.check(n, tv(n), make_db(n))),
    0,
  )
}

// -- Inter-procedural --
fn interproc_def_taint() -> Bool {
  // Function def with tainted param should seed the param
  // Then assign inside the function propagates taint
  // Then the function name itself is marked as tainted
  // Then result = get_url() gets tainted via interprocedural
  let n = [
    Node(
      node_type: Def,
      name: "get_url",
      args: [arg_(ArgVar, "request")],
      line: 1,
      taint: False,
      file: "test.cr",
    ),
    Node(
      node_type: Assign,
      name: "url",
      args: [arg_(ArgVar, "request")],
      line: 2,
      taint: False,
      file: "test.cr",
    ),
    Node(
      node_type: Assign,
      name: "result",
      args: [arg_(ArgCall, "get_url")],
      line: 10,
      taint: False,
      file: "other.cr",
    ),
    Node(
      node_type: Call,
      name: "HTTP::Client.get",
      args: [arg_(ArgVar, "result")],
      line: 11,
      taint: False,
      file: "other.cr",
    ),
  ]
  let db = make_db(n)
  let tainted = taint.tainted_vars_list(db)
  assert_eq("interproc: result tainted", taint.is_tainted(db, "result"), True)
  && assert_eq(
    "interproc: ssrf found",
    list.length(ssrf.check(n, tainted, db)),
    1,
  )
}

// -- Runner --
pub fn main() {
  let tests = [
    #("taint: extracts", taint_extracts()),
    #("taint: propagates", taint_propagates()),
    #("taint: multi-hop", taint_multi_hop()),
    #("taint: no false", taint_no_false()),
    #("taint: flow", taint_flow()),
    #("ssrf: var", ssrf_var()),
    #("ssrf: literal", ssrf_literal()),
    #("ssrf: tainted", ssrf_tainted()),
    #("ssrf: all", ssrf_all()),
    #("ssrf: non-http", ssrf_non_http()),
    #("cmdi: system", cmdi_system()),
    #("cmdi: os.command", cmdi_os_cmd()),
    #("cmdi: literal", cmdi_literal()),
    #("cmdi: db whitelist", cmdi_db()),
    #("pt: file", pt_file()),
    #("pt: literal", pt_literal()),
    #("pt: interp", pt_interp()),
    #("sqli: query", sqli_query()),
    #("sqli: literal", sqli_literal()),
    #("int: all rules", all_rules()),
    #("int: empty", empty()),
    #("sanitizer: uri", sanitizer_uri()),
    #("sanitizer: string", sanitizer_string()),
    #("sanitizer: path", sanitizer_path()),
    #("interproc: def taint", interproc_def_taint()),
  ]
  let failures = list.filter(tests, fn(t) { !t.1 })
  io.println("")
  case list.length(failures) {
    0 ->
      io.println("All " <> int.to_string(list.length(tests)) <> " tests passed")
    _ -> {
      io.println(
        int.to_string(list.length(failures))
        <> " of "
        <> int.to_string(list.length(tests))
        <> " tests FAILED:",
      )
      list.each(failures, fn(f) { io.println("  - " <> f.0) })
    }
  }
  io.println("")
}
