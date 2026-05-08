import catseye/node.{
  type Arg, type FlowStep, type Node, ArgCall, ArgVar, Assign, Def, FlowStep,
  all_args_literal,
}
import gleam/int
import gleam/list
import gleam/result
import gleam/string

// ── Types ──────────────────────────────────────────────────────────────

pub type TaintRecord {
  TaintRecord(
    var_name: String,
    file: String,
    line: Int,
    description: String,
    source_var: String,
    /// Field path for field-sensitive tracking.
    /// "" means whole variable is tainted.
    field: String,
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

/// Field names that carry taint (from request.params, etc.)
const tainted_fields = [
  "params", "query", "body", "headers", "cookies", "url", "path", "data", "form",
  "files", "host", "referer", "cookie",
]

// ── Public API ─────────────────────────────────────────────────────────

pub fn build_taint_db(nodes: List(Node)) -> TaintDB {
  let seeded = seed_sources(nodes, [])
  let propagated = propagate(nodes, seeded)
  let with_returns = track_return_taint(nodes, propagated)
  propagate(nodes, with_returns)
}

pub fn build_taint_db_with_config(
  nodes: List(Node),
  extra_sources: List(String),
  extra_sanitizers: List(String),
) -> TaintDB {
  let seeded = seed_sources_with_config(nodes, [], extra_sources)
  let propagated = propagate_with_sanitizers(nodes, seeded, extra_sanitizers)
  let with_returns = track_return_taint(nodes, propagated)
  propagate_with_sanitizers(nodes, with_returns, extra_sanitizers)
}

/// Get tainted variable names (unique, de-duplicated)
pub fn build_tainted_vars(nodes: List(Node)) -> List(String) {
  build_taint_db(nodes) |> tainted_vars_list()
}

pub fn tainted_vars_list(db: TaintDB) -> List(String) {
  db
  |> list.map(fn(r) { r.var_name })
  |> list.unique()
}

/// Check if a variable is tainted in ANY file (legacy API for rules)
pub fn is_tainted(db: TaintDB, var: String) -> Bool {
  list.any(db, fn(r) { r.var_name == var })
}

/// Check if a variable is tainted within a specific file
pub fn is_tainted_in_file(db: TaintDB, var: String, file: String) -> Bool {
  list.any(db, fn(r) { r.var_name == var && r.file == file })
}

/// Check if a variable+field combination is tainted.
pub fn is_tainted_field(db: TaintDB, var: String, field: String) -> Bool {
  case field {
    "" -> is_tainted(db, var)
    _ ->
      list.any(db, fn(r) {
        r.var_name == var && { r.field == "" || r.field == field }
      })
  }
}

// ── Sanitizer checking ─────────────────────────────────────────────────

pub fn is_sanitizer(call_name: String) -> Bool {
  list.any(sanitizers, fn(s) { string.contains(call_name, s) })
}

pub fn is_sanitizer_with_extra(call_name: String, extra: List(String)) -> Bool {
  is_sanitizer(call_name)
  || list.any(extra, fn(s) { string.contains(call_name, s) })
}

// ── Field extraction ───────────────────────────────────────────────────

/// Extract field from a call like "req.params" → Some("params")
pub fn extract_field_access(name: String) -> Result(String, Nil) {
  case string.split(name, ".") {
    [_obj, field] ->
      case list.contains(tainted_fields, field) {
        True -> Ok(field)
        False -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

/// Extract field from Arg if present (from extractor field tracking)
pub fn extract_arg_field(arg: Arg) -> String {
  arg.field
}

// ── Scope handling ─────────────────────────────────────────────────────

/// Find the Def node that a given node belongs to
pub fn enclosing_def(nodes: List(Node), node: Node) -> Result(Node, Nil) {
  nodes
  |> list.filter(fn(n) {
    n.node_type == Def && n.file == node.file && n.line < node.line
  })
  |> list.sort(fn(a, b) { int.compare(b.line, a.line) })
  |> list.first()
}

/// Get the line number of the next def in the same file after the given def.
pub fn next_def_line(nodes: List(Node), defn: Node) -> Int {
  nodes
  |> list.filter(fn(n) {
    n.node_type == Def && n.file == defn.file && n.line > defn.line
  })
  |> list.map(fn(n) { n.line })
  |> list.sort(fn(a, b) { int.compare(a, b) })
  |> list.first()
  |> result.unwrap(999_999)
}

/// Get variables defined in a given scope (function)
pub fn scope_vars(nodes: List(Node), defn: Node) -> List(String) {
  let ndl = next_def_line(nodes, defn)
  nodes
  |> list.filter(fn(n) {
    n.file == defn.file
    && n.line > defn.line
    && n.line < ndl
    && n.node_type == Assign
  })
  |> list.map(fn(n) { n.name })
}

// ── Suspect detection ──────────────────────────────────────────────────

pub fn arg_is_tainted(tainted: List(String), arg: Arg) -> Bool {
  case arg.arg_type {
    ArgVar -> list.contains(tainted, arg.value)
    ArgCall -> False
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
      { node.taint || args_contain_tainted(tainted, node) }
      && !all_args_literal(node)
  }
}

pub fn is_suspect_with_extra(
  node: Node,
  tainted: List(String),
  extra_sanitizers: List(String),
) -> Bool {
  let has_sanitized =
    list.any(node.args, fn(a) {
      a.arg_type == ArgCall
      && is_sanitizer_with_extra(a.value, extra_sanitizers)
    })
  case has_sanitized {
    True -> False
    False ->
      { node.taint || args_contain_tainted(tainted, node) }
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

fn seed_sources(nodes: List(Node), db: TaintDB) -> TaintDB {
  seed_sources_with_config(nodes, db, [])
}

fn seed_sources_with_config(
  nodes: List(Node),
  db: TaintDB,
  extra_sources: List(String),
) -> TaintDB {
  let all_sources =
    list.append(
      [
        "params", "request", "req", "get_body", "query", "io.get_line",
        "dynamic.unsafe_coerce", "request.get_body", "user_url", "user_input",
        "url", "path", "cmd", "command", "input", "env", "ARGV", "STDIN", "gets",
      ],
      extra_sources,
    )
  let is_source = fn(name: String) -> Bool {
    list.any(all_sources, fn(p) { string.contains(name, p) })
  }
  // Phase 1a: function params named like taint sources
  let param_seeds =
    nodes
    |> list.filter(fn(n) { n.node_type == Def })
    |> list.flat_map(fn(n) {
      n.args
      |> list.filter(fn(a) { is_source(a.value) })
      |> list.map(fn(a) {
        // Include field from arg if present (e.g., params["url"])
        let field = extract_arg_field(a)
        #(a.value, n.file, n.line, field)
      })
    })
    |> list.fold(db, fn(acc, entry) {
      let name = entry.0
      let file = entry.1
      let line = entry.2
      let field = entry.3
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
              field: field,
            ),
          ])
      }
    })
  // Phase 1b: extractor-flagged assignments (taint=true)
  // Skip if RHS is a sanitizer call (extractor doesn't know about sanitizers)
  nodes
  |> list.filter(fn(n) {
    n.node_type == Assign && n.taint && !is_sanitized_rhs(n.args)
  })
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
                field: field_from_args(node.args),
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
                field: field_from_args(node.args),
              ),
            ])
        }
    }
  })
}

/// Extract field from the first arg that has one
fn field_from_args(args: List(Arg)) -> String {
  case args {
    [] -> ""
    [a, ..rest] ->
      case a.field != "" {
        True -> a.field
        False -> field_from_args(rest)
      }
  }
}

// ── Return value taint tracking ────────────────────────────────────────

fn track_return_taint(nodes: List(Node), db: TaintDB) -> TaintDB {
  let defs =
    nodes
    |> list.filter(fn(n) { n.node_type == Def })
  list.fold(defs, db, fn(acc, defn) {
    let fn_name = defn.name
    let ndl = next_def_line(nodes, defn)
    let fn_assigns =
      nodes
      |> list.filter(fn(n) {
        n.node_type == Assign
        && n.file == defn.file
        && n.line > defn.line
        && n.line < ndl
      })
    let fn_tainted =
      list.any(fn_assigns, fn(n) { has_record(acc, n.name) || n.taint })
    case fn_tainted && !has_record(acc, fn_name) {
      True ->
        list.append(acc, [
          TaintRecord(
            var_name: fn_name,
            file: defn.file,
            line: defn.line,
            description: fn_name <> " returns tainted data",
            source_var: "",
            field: "",
          ),
        ])
      False -> acc
    }
  })
}

// ── Inter-procedural propagation ───────────────────────────────────────

fn propagate_interprocedural(nodes: List(Node), db: TaintDB) -> TaintDB {
  list.fold(nodes, db, fn(acc, node) {
    case node.node_type == Assign && !has_record(acc, node.name) {
      True -> {
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
                field: "",
              ),
            ])
          Error(Nil) ->
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
                    field: "",
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
  propagate_with_sanitizers(nodes, db, [])
}

fn propagate_with_sanitizers(
  nodes: List(Node),
  db: TaintDB,
  extra_sanitizers: List(String),
) -> TaintDB {
  let new_db = do_propagate(nodes, db, extra_sanitizers)
  case list.length(new_db) > list.length(db) {
    True -> propagate_with_sanitizers(nodes, new_db, extra_sanitizers)
    False -> {
      let inter_db = propagate_interprocedural(nodes, new_db)
      case list.length(inter_db) > list.length(new_db) {
        True -> propagate_with_sanitizers(nodes, inter_db, extra_sanitizers)
        False -> new_db
      }
    }
  }
}

/// File-scoped propagation: an assign in file X can only pick up taint
/// from vars in the same file X.
fn do_propagate(
  nodes: List(Node),
  db: TaintDB,
  extra_sanitizers: List(String),
) -> TaintDB {
  list.fold(nodes, db, fn(acc, node) {
    case node.node_type == Assign && !has_record(acc, node.name) {
      True ->
        case is_sanitized_assign(node, extra_sanitizers) {
          True -> acc
          False ->
            case first_var_in_file_db(node.args, acc, node.file) {
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
                    field: field_from_args(node.args),
                  ),
                ])
              Error(Nil) -> acc
            }
        }
      False -> acc
    }
  })
}

/// Check if an assignment's RHS is a sanitizer call
fn is_sanitized_assign(node: Node, extra_sanitizers: List(String)) -> Bool {
  list.any(node.args, fn(a) {
    a.arg_type == ArgCall && is_sanitizer_with_extra(a.value, extra_sanitizers)
  })
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Check if the RHS of an assignment is a sanitizer call
fn is_sanitized_rhs(args: List(Arg)) -> Bool {
  list.any(args, fn(a) { a.arg_type == ArgCall && is_sanitizer(a.value) })
}

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

/// File-scoped lookup: find first tainted var arg that's tainted in the same file
fn first_var_in_file_db(
  args: List(Arg),
  db: TaintDB,
  file: String,
) -> Result(String, Nil) {
  case args {
    [] -> Error(Nil)
    [a, ..rest] ->
      case a.arg_type == ArgVar && is_tainted_in_file(db, a.value, file) {
        True -> Ok(a.value)
        False -> first_var_in_file_db(rest, db, file)
      }
  }
}
