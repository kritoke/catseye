import catseye/node.{
  type Arg, type FlowStep, type Node, ArgCall, ArgLiteral, ArgVar, Assign, Call,
  Def, FlowStep, all_args_literal, has_var_args,
}
import gleam/int
import gleam/list
import gleam/string

// ── Types ──────────────────────────────────────────────────────────────

pub type TaintRecord {
  TaintRecord(
    var_name: String,
    file: String,
    line: Int,
    description: String,
    source_var: String,
  )
}

pub type TaintDB =
  List(TaintRecord)

/// Functions known to return tainted values when given tainted args
pub type TaintedFunction {
  TaintedFunction(name: String, file: String, line: Int, params: List(String))
}

/// Sanitizer functions that cleanse taint
const sanitizers = [
  "URI.parse", "URI.encode", "URI.decode", "Path.posix", "Path.basename",
  "Path.dirname", "String.strip", "String.trim", "String.slice", "Int.parse",
  "Float.parse", "validator.", "sanitize.", "escape.", "encode.", "cgi.escape",
  "html.escape",
]

// ── Public API ─────────────────────────────────────────────────────────

pub fn build_taint_db(nodes: List(Node)) -> TaintDB {
  let seeded = seed_sources(nodes, [])
  let propagated = propagate(nodes, seeded)
  let with_returns = track_return_taint(nodes, propagated)
  // Second propagation pass to spread return-taint
  propagate(nodes, with_returns)
}

pub fn build_tainted_vars(nodes: List(Node)) -> List(String) {
  build_taint_db(nodes) |> list.map(fn(r) { r.var_name })
}

pub fn tainted_vars_list(db: TaintDB) -> List(String) {
  list.map(db, fn(r) { r.var_name })
}

pub fn is_tainted(db: TaintDB, var: String) -> Bool {
  list.any(db, fn(r) { r.var_name == var })
}

// ── Sanitizer checking ─────────────────────────────────────────────────

pub fn is_sanitizer(call_name: String) -> Bool {
  list.any(sanitizers, fn(s) { string.contains(call_name, s) })
}

// ── Suspect detection ──────────────────────────────────────────────────

pub fn arg_is_tainted(tainted: List(String), arg: Arg) -> Bool {
  case arg.arg_type {
    ArgVar -> list.contains(tainted, arg.value)
    ArgCall -> string.contains(arg.value, "<interpolation>")
    _ -> False
  }
}

pub fn args_contain_tainted(tainted: List(String), node: Node) -> Bool {
  list.any(node.args, fn(a) { arg_is_tainted(tainted, a) })
}

pub fn is_suspect(node: Node, tainted: List(String)) -> Bool {
  let has_sanitized =
    list.any(node.args, fn(a) { a.arg_type == ArgCall && is_sanitizer(a.value) })
  case has_sanitized {
    True -> False
    False ->
      {
        node.taint || has_var_args(node) || args_contain_tainted(tainted, node)
      }
      && !all_args_literal(node)
  }
}

pub fn var_names_from_args(args: List(Arg)) -> String {
  args
  |> list.filter(fn(a) { a.arg_type == ArgVar })
  |> list.map(fn(a) { a.value })
  |> string.join(", ")
}

// ── Flow tracing ───────────────────────────────────────────────────────

pub fn trace_flow(db: TaintDB, var: String) -> List(FlowStep) {
  case list.find(db, fn(r) { r.var_name == var }) {
    Ok(record) -> {
      let step =
        FlowStep(
          file: record.file,
          line: record.line,
          message: record.description,
        )
      case record.source_var == "" {
        True -> [step]
        False -> list.append(trace_flow(db, record.source_var), [step])
      }
    }
    Error(Nil) -> []
  }
}

pub fn build_finding_flow(db: TaintDB, node: Node) -> List(FlowStep) {
  let source_steps =
    node.args
    |> list.filter(fn(a) { a.arg_type == ArgVar && is_tainted(db, a.value) })
    |> list.map(fn(a) { trace_flow(db, a.value) })
    |> list.flatten()
    |> dedup_steps([])
  let sink =
    FlowStep(
      file: node.file,
      line: node.line,
      message: "Sink: " <> node.name <> " called with tainted data",
    )
  list.append(source_steps, [sink])
}

fn dedup_steps(steps: List(FlowStep), seen: List(String)) -> List(FlowStep) {
  case steps {
    [] -> []
    [step, ..rest] -> {
      let key = step.file <> ":" <> int.to_string(step.line)
      case list.contains(seen, key) {
        True -> dedup_steps(rest, seen)
        False ->
          list.append([step], dedup_steps(rest, list.append(seen, [key])))
      }
    }
  }
}

// ── Seeding ────────────────────────────────────────────────────────────

fn is_taint_source_name(name: String) -> Bool {
  list.any(
    [
      "params", "request", "req", "get_body", "query", "io.get_line",
      "dynamic.unsafe_coerce", "request.get_body", "user_url", "user_input",
      "url", "path", "cmd", "command", "input", "env", "ARGV", "STDIN", "gets",
    ],
    fn(p) { string.contains(name, p) },
  )
}

fn seed_sources(nodes: List(Node), db: TaintDB) -> TaintDB {
  // Phase 1a: function params named like taint sources
  let param_seeds =
    nodes
    |> list.filter(fn(n) { n.node_type == Def })
    |> list.flat_map(fn(n) {
      n.args
      |> list.filter(fn(a) { is_taint_source_name(a.value) })
      |> list.map(fn(a) { #(a.value, n.file, n.line) })
    })
    |> list.fold(db, fn(acc, entry) {
      let name = entry.0
      let file = entry.1
      let line = entry.2
      case has_record(acc, name) {
        True -> acc
        False ->
          list.append(acc, [
            TaintRecord(
              var_name: name,
              file: file,
              line: line,
              description: name <> " is a taint source (parameter)",
              source_var: "",
            ),
          ])
      }
    })
  // Phase 1b: extractor-flagged assignments (taint=true)
  nodes
  |> list.filter(fn(n) { n.node_type == Assign && n.taint })
  |> list.fold(param_seeds, fn(acc, node) {
    case has_record(acc, node.name) {
      True -> acc
      False ->
        case first_var_in_db(node.args, acc) {
          Ok(from_var) ->
            list.append(acc, [
              TaintRecord(
                var_name: node.name,
                file: node.file,
                line: node.line,
                description: node.name <> " assigned from tainted: " <> from_var,
                source_var: from_var,
              ),
            ])
          Error(Nil) ->
            list.append(acc, [
              TaintRecord(
                var_name: node.name,
                file: node.file,
                line: node.line,
                description: node.name <> " tainted via source",
                source_var: "",
              ),
            ])
        }
    }
  })
}

// ── Return value taint tracking ────────────────────────────────────────

/// When a function's body ends with a tainted variable reference,
/// calls to that function propagate taint to the caller's scope.
/// This handles patterns like:
///   def get_url(params) { params["url"] }  → get_url is tainted
///   url = get_url(params)                  → url is tainted
fn track_return_taint(nodes: List(Node), db: TaintDB) -> TaintDB {
  // Find all function definitions
  let defs =
    nodes
    |> list.filter(fn(n) { n.node_type == Def })
  // For each def, check if its last call/assign involves tainted data
  // If so, mark the function name as tainted
  list.fold(defs, db, fn(acc, defn) {
    let fn_name = defn.name
    // Find calls inside this function that assign to the result
    let fn_calls =
      nodes
      |> list.filter(fn(n) {
        // Assignments inside this function's scope (simplified: same file,
        // line > def line, before next def)
        n.node_type == Assign && n.file == defn.file && n.line > defn.line
      })
    // Check if any assign in this function produces a tainted result
    let fn_tainted =
      list.any(fn_calls, fn(n) { has_record(acc, n.name) || n.taint })
    case fn_tainted && !has_record(acc, fn_name) {
      True ->
        list.append(acc, [
          TaintRecord(
            var_name: fn_name,
            file: defn.file,
            line: defn.line,
            description: fn_name <> " returns tainted data",
            source_var: "",
          ),
        ])
      False -> acc
    }
  })
}

// ── Inter-procedural propagation ───────────────────────────────────────

/// When we see `call foo(x)` and `foo` is a known tainted function,
/// treat the call result as tainted.
fn propagate_interprocedural(nodes: List(Node), db: TaintDB) -> TaintDB {
  list.fold(nodes, db, fn(acc, node) {
    case node.node_type == Assign && !has_record(acc, node.name) {
      True -> {
        // Check if RHS is a call to a tainted function
        let tainted_call =
          node.args
          |> list.find(fn(a) {
            a.arg_type == ArgCall && has_record(acc, a.value)
          })
        case tainted_call {
          Ok(a) ->
            list.append(acc, [
              TaintRecord(
                var_name: node.name,
                file: node.file,
                line: node.line,
                description: node.name
                  <> " assigned from tainted call: "
                  <> a.value,
                source_var: a.value,
              ),
            ])
          Error(Nil) ->
            // Check if RHS references a tainted var through call args
            case first_var_in_db(node.args, acc) {
              Ok(from_var) ->
                list.append(acc, [
                  TaintRecord(
                    var_name: node.name,
                    file: node.file,
                    line: node.line,
                    description: node.name
                      <> " assigned from tainted: "
                      <> from_var,
                    source_var: from_var,
                  ),
                ])
              Error(Nil) -> acc
            }
        }
      }
      False -> acc
    }
  })
}

// ── Fixed-point propagation ────────────────────────────────────────────

fn propagate(nodes: List(Node), db: TaintDB) -> TaintDB {
  let new_db = do_propagate(nodes, db)
  case list.length(new_db) > list.length(db) {
    True -> propagate(nodes, new_db)
    False -> {
      // After basic propagation, do interprocedural pass
      let inter_db = propagate_interprocedural(nodes, new_db)
      case list.length(inter_db) > list.length(new_db) {
        True -> propagate(nodes, inter_db)
        False -> new_db
      }
    }
  }
}

fn do_propagate(nodes: List(Node), db: TaintDB) -> TaintDB {
  list.fold(nodes, db, fn(acc, node) {
    case node.node_type == Assign && !has_record(acc, node.name) {
      True ->
        case first_var_in_db(node.args, acc) {
          Ok(from_var) ->
            list.append(acc, [
              TaintRecord(
                var_name: node.name,
                file: node.file,
                line: node.line,
                description: node.name <> " assigned from tainted: " <> from_var,
                source_var: from_var,
              ),
            ])
          Error(Nil) -> acc
        }
      False -> acc
    }
  })
}

// ── Helpers ────────────────────────────────────────────────────────────

fn has_record(db: TaintDB, var: String) -> Bool {
  list.any(db, fn(r) { r.var_name == var })
}

fn first_var_in_db(args: List(Arg), db: TaintDB) -> Result(String, Nil) {
  case args {
    [] -> Error(Nil)
    [a, ..rest] ->
      case a.arg_type == ArgVar && has_record(db, a.value) {
        True -> Ok(a.value)
        False -> first_var_in_db(rest, db)
      }
  }
}
