(* lib/catseye_cli/dot.ml
   Graphviz DOT export for call graph and reachability visualization.

   Exports the call adjacency map from Predator Vision as a DOT file
   that can be rendered with `dot -Tpng graph.dot -o graph.png`.

   Entry points are colored green, reachable functions blue,
   unreachable/dormant functions gray, and functions containing
   findings (sinks) are colored red. *)

open Catseye_types
open Catseye_engine.Reachability

(* ── DOT helpers ────────────────────────────────────────────────────── *)

(** Sanitize a string for DOT node IDs (replace dots/colons with underscores) *)
let sanitize_id (s : string) : string =
  let buf = Bytes.create (String.length s) in
  String.iteri (fun i c ->
    Bytes.set buf i (match c with
      | '.' | ':' | '/' | ' ' | '-' -> '_'
      | c -> c)
  ) s;
  Bytes.to_string buf

(** Make a unique node ID from function name + file *)
let node_id (func_name : string) (file : string) : string =
  sanitize_id (Filename.basename file ^ "_" ^ func_name)

(* ── Classification ─────────────────────────────────────────────────── *)

type node_class =
  | Entry
  | Sink of string  (** rule name *)
  | Reachable
  | Dormant

let classify_nodes (adj : call_adjacency)
    (entries : entry_point list)
    (reachable : StringSet.t)
    (findings : Finding.t list)
    (scopes : scope_info list)
    : (string * string * node_class) list =
  (* Collect entry point function names *)
  let entry_names = List.fold_left (fun acc e ->
    StringSet.add e.function_name acc
  ) StringSet.empty entries in
  (* Collect sink function names *)
  let sink_map = Hashtbl.create 16 in
  List.iter (fun f ->
    match find_scope scopes f.Finding.file f.Finding.line with
    | Some s ->
      let existing = try Hashtbl.find sink_map s.func_name with Not_found -> [] in
      Hashtbl.replace sink_map s.func_name (f.Finding.rule :: existing)
    | None -> ()
  ) findings;
  (* Collect all function names from adjacency *)
  let all_funcs = ref StringSet.empty in
  StringMap.iter (fun caller edges ->
    all_funcs := StringSet.add caller !all_funcs;
    List.iter (fun (called, _, _) ->
      all_funcs := StringSet.add called !all_funcs
    ) edges
  ) adj;
  (* Add entry points that may not be in adjacency *)
  List.iter (fun e ->
    all_funcs := StringSet.add e.function_name !all_funcs
  ) entries;
  (* Classify each function — find its file *)
  let func_file = Hashtbl.create 32 in
  List.iter (fun s ->
    if not (Hashtbl.mem func_file s.func_name) then
      Hashtbl.replace func_file s.func_name s.file
  ) scopes;
  List.iter (fun e ->
    if not (Hashtbl.mem func_file e.function_name) then
      Hashtbl.replace func_file e.function_name e.file
  ) entries;
  StringSet.elements !all_funcs
  |> List.filter_map (fun name ->
    let file = try Hashtbl.find func_file name with Not_found -> "?" in
    let cls =
      if Hashtbl.mem sink_map name then
        Sink (String.concat ", " (Hashtbl.find sink_map name))
      else if StringSet.mem name entry_names then
        Entry
      else if StringSet.mem name reachable then
        Reachable
      else
        Dormant
    in
    Some (name, file, cls)
  )

(* ── DOT color scheme ───────────────────────────────────────────────── *)

let node_color = function
  | Entry -> "#4CAF50"      (* green *)
  | Sink _ -> "#F44336"     (* red *)
  | Reachable -> "#2196F3"  (* blue *)
  | Dormant -> "#9E9E9E"    (* gray *)

let node_shape = function
  | Entry -> "diamond"
  | Sink _ -> "box"
  | Reachable -> "ellipse"
  | Dormant -> "ellipse"

let node_style = function
  | Entry -> "filled,bold"
  | Sink _ -> "filled,bold"
  | Reachable -> "filled"
  | Dormant -> "filled,dashed"

(* ── Export ──────────────────────────────────────────────────────────── *)

(** Export the call graph as a DOT string.
    Entry points, reachable functions, sinks, and dormant functions
    are visually distinguished by color and shape. *)
let to_dot (nodes : Security_node.t list)
    (findings : Finding.t list)
    ~(custom_patterns : string list) : string =
  let buf = Buffer.create 4096 in
  let pr fmt = Printf.bprintf buf fmt in

  (* Build analysis structures *)
  let scopes = build_scopes nodes in
  let adj = build_call_adjacency nodes scopes in
  let entries = detect_entry_points nodes custom_patterns in
  let reachable = reachable_from entries adj in

  (* Classify nodes *)
  let classified = classify_nodes adj entries reachable findings scopes in

  (* DOT header *)
  pr "digraph catseye_callgraph {\n";
  pr "  rankdir=LR;\n";
  pr "  fontname=\"Helvetica\";\n";
  pr "  label=\"Catseye Call Graph — %d functions, %d entry points, %d findings\";\n"
    (List.length classified) (List.length entries) (List.length findings);
  pr "  labelloc=t;\n";
  pr "  fontsize=14;\n\n";

  (* Legend *)
  pr "  subgraph cluster_legend {\n";
  pr "    label=\"Legend\";\n";
  pr "    style=dashed;\n";
  pr "    node [fontsize=10];\n";
  pr "    leg_entry [shape=diamond,style=filled,color=\"#4CAF50\",label=\"Entry Point\"];\n";
  pr "    leg_sink [shape=box,style=filled,color=\"#F44336\",label=\"Sink (Finding)\"];\n";
  pr "    leg_reach [shape=ellipse,style=filled,color=\"#2196F3\",label=\"Reachable\"];\n";
  pr "    leg_dorm [shape=ellipse,style=filled,dashed,color=\"#9E9E9E\",label=\"Dormant\"];\n";
  pr "  }\n\n";

  (* Nodes *)
  pr "  /* Nodes */\n";
  List.iter (fun (name, file, cls) ->
    let id = node_id name file in
    let color = node_color cls in
    let shape = node_shape cls in
    let style = node_style cls in
    let label = match cls with
      | Sink rules -> Printf.sprintf "%s\\n[%s]" name rules
      | _ -> name
    in
    pr "  %s [label=\"%s\",shape=%s,style=\"%s\",color=\"%s\",fontcolor=\"white\"];\n"
      id label shape style color
  ) classified;
  pr "\n";

  (* Edges *)
  pr "  /* Edges */\n";
  StringMap.iter (fun caller edges ->
    (* Find caller file *)
    let caller_file = try
      let s = List.find (fun s -> s.func_name = caller) scopes in s.file
    with Not_found -> "?"
    in
    let caller_id = node_id caller caller_file in
    List.iter (fun (called, called_file, _line) ->
      let called_id = node_id called called_file in
      (* Highlight edges to sinks *)
      let is_sink = List.exists (fun f ->
        match find_scope scopes f.Finding.file f.Finding.line with
        | Some s -> s.func_name = called
        | None -> false
      ) findings in
      if is_sink then
        pr "  %s -> %s [color=\"#F44336\",penwidth=2.0];\n" caller_id called_id
      else
        pr "  %s -> %s;\n" caller_id called_id
    ) edges
  ) adj;
  pr "}\n";

  Buffer.contents buf

(** Write DOT output to a file or stdout. *)
let output_dot (nodes : Security_node.t list)
    (findings : Finding.t list)
    ~(custom_patterns : string list)
    (output_path : string) : unit =
  let content = to_dot nodes findings ~custom_patterns in
  if output_path <> "" then begin
    let oc = open_out output_path in
    output_string oc content;
    close_out oc;
    Printf.printf "Call graph written to %s\n" output_path
  end else
    print_string content
