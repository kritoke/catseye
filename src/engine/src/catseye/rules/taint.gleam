import catseye/node.{
  type Arg, type FlowStep, type Node, ArgCall, ArgVar, Assign, Def, FlowStep,
  all_args_literal, has_var_args,
}
import gleam/int
import gleam/list
import gleam/string

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

pub fn build_taint_db(nodes: List(Node)) -> TaintDB {
  let seeded = seed_sources(nodes, [])
  propagate(nodes, seeded)
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
  { node.taint || has_var_args(node) || args_contain_tainted(tainted, node) }
  && !all_args_literal(node)
}

pub fn var_names_from_args(args: List(Arg)) -> String {
  args
  |> list.filter(fn(a) { a.arg_type == ArgVar })
  |> list.map(fn(a) { a.value })
  |> string.join(", ")
}

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

fn is_taint_source_name(name: String) -> Bool {
  list.any(
    [
      "params", "request", "req", "get_body", "query", "io.get_line",
      "dynamic.unsafe_coerce", "request.get_body",
    ],
    fn(p) { string.contains(name, p) },
  )
}

fn seed_sources(nodes: List(Node), db: TaintDB) -> TaintDB {
  let param_seeds =
    nodes
    |> list.filter(fn(n) { n.node_type == Def })
    |> list.flat_map(fn(n) {
      n.args
      |> list.filter(fn(a) { is_taint_source_name(a.value) })
      |> list.map(fn(a) { a.value })
    })
    |> list.fold(db, fn(acc, name) {
      case has_record(acc, name) {
        True -> acc
        False ->
          list.append(acc, [
            TaintRecord(
              var_name: name,
              file: "",
              line: 0,
              description: name <> " is a taint source (parameter)",
              source_var: "",
            ),
          ])
      }
    })
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

fn propagate(nodes: List(Node), db: TaintDB) -> TaintDB {
  let new_db = do_propagate(nodes, db)
  case list.length(new_db) > list.length(db) {
    True -> propagate(nodes, new_db)
    False -> db
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
