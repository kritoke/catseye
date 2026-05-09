(* lib/catseye_types/dag_types.ml *)

type dag_node_type =
  | Source
  | Assignment
  | Function_return
  | Call
  | Sanitizer
  | Sink

type dag_node = {
  id : int;
  node_type : dag_node_type;
  file : string;
  line : int;
  label : string;
  var_name : string;
  language : string;
}

type dag_edge_type =
  | Taint_propagation
  | Sanitization_break
  | Inter_procedural

type dag_edge = {
  from_id : int;
  to_id : int;
  edge_type : dag_edge_type;
  description : string;
}

type vulnerability_dag = {
  rule_id : string;
  severity : string;
  root_sink : dag_node;
  nodes : dag_node list;
  edges : dag_edge list;
  source_paths : int list list;       (* all paths from sources to sink *)
  sanitized_paths : int list list;    (* paths that go through a sanitizer *)
}

(* JSON encoding *)
let string_of_dag_node_type = function
  | Source -> "source"
  | Assignment -> "assignment"
  | Function_return -> "function_return"
  | Call -> "call"
  | Sanitizer -> "sanitizer"
  | Sink -> "sink"

let string_of_dag_edge_type = function
  | Taint_propagation -> "taint_propagation"
  | Sanitization_break -> "sanitization_break"
  | Inter_procedural -> "inter_procedural"

let encode_dag_node (n : dag_node) : Yojson.Safe.t =
  `Assoc
    [ ("id", `Int n.id)
    ; ("node_type", `String (string_of_dag_node_type n.node_type))
    ; ("file", `String n.file)
    ; ("line", `Int n.line)
    ; ("label", `String n.label)
    ; ("var_name", `String n.var_name)
    ; ("language", `String n.language)
    ]

let encode_dag_edge (e : dag_edge) : Yojson.Safe.t =
  `Assoc
    [ ("from", `Int e.from_id)
    ; ("to", `Int e.to_id)
    ; ("edge_type", `String (string_of_dag_edge_type e.edge_type))
    ; ("description", `String e.description)
    ]

let encode (dag : vulnerability_dag) : Yojson.Safe.t =
  `Assoc
    [ ("rule_id", `String dag.rule_id)
    ; ("severity", `String dag.severity)
    ; ("root_sink_id", `Int dag.root_sink.id)
    ; ("nodes", `List (List.map encode_dag_node dag.nodes))
    ; ("edges", `List (List.map encode_dag_edge dag.edges))
    ; ("source_paths", `List (List.map (fun p -> `List (List.map (fun i -> `Int i) p)) dag.source_paths))
    ; ("sanitized_paths", `List (List.map (fun p -> `List (List.map (fun i -> `Int i) p)) dag.sanitized_paths))
    ]

(* DOT (GraphViz) output *)
let dag_node_color = function
  | Source -> "red"
  | Sink -> "orange"
  | Sanitizer -> "green"
  | _ -> "black"

let dag_edge_style = function
  | Taint_propagation -> "solid"
  | Sanitization_break -> "dashed"
  | Inter_procedural -> "dotted"

let to_dot (dag : vulnerability_dag) : string =
  let buf = Buffer.create 1024 in
  Buffer.add_string buf "digraph vulnerability {\n";
  Buffer.add_string buf "  rankdir=TB;\n";
  Buffer.add_string buf "  node [shape=box];\n";
  List.iter (fun n ->
    let color = dag_node_color n.node_type in
    let label = String.concat "" [
      String.sub n.file
        (max 0 (String.length n.file - 30))
        (min 30 (String.length n.file));
      ":"; string_of_int n.line; " "; n.label
    ] in
    Buffer.add_string buf (Printf.sprintf
      "  n%d [label=\"%s\" color=%s];\n" n.id label color)
  ) dag.nodes;
  List.iter (fun e ->
    let style = dag_edge_style e.edge_type in
    Buffer.add_string buf (Printf.sprintf
      "  n%d -> n%d [style=%s label=\"%s\"];\n"
      e.from_id e.to_id style e.description)
  ) dag.edges;
  Buffer.add_string buf "}\n";
  Buffer.contents buf
