(* lib/catseye_cli/dot.ml
   Graphviz DOT export for call graph and reachability visualization.

   Uses ocamlgraph's Graphviz.Dot functor for DOT generation.
   The call graph is built from Predator Vision's call_adjacency map,
   then rendered with styled nodes based on classification
   (Entry=green, Sink=red, Reachable=blue, Dormant=gray). *)

open Base

open Catseye_types
open Catseye_engine.Reachability

(* ── Call graph using ocamlgraph ────────────────────────────────────── *)

(** String-keyed directed graph for call adjacency *)
module CallGraph = Graph.Imperative.Digraph.Concrete (struct
  type t = string
  let compare = String.compare
  let hash = Stdlib.Hashtbl.hash
  let equal = String.equal
end)

(* ── Classification ─────────────────────────────────────────────────── *)

type node_class =
  | Entry
  | Sink of string  (** rule name *)
  | Reachable
  | Dormant

(** Classify all functions in the call graph. *)
let classify_nodes (adj : call_adjacency)
    (entries : entry_point list)
    (reachable : string Set.Poly.t)
    (findings : Finding.t list)
    (scopes : scope_info list)
    : (string * string * node_class) list =
  let entry_names = List.fold_left ~init:Set.Poly.empty ~f:(fun acc e ->
    Set.Poly.add acc e.function_name
  ) entries in
  let sink_map = Stdlib.Hashtbl.create 16 in
  List.iter ~f:(fun f ->
    match find_scope scopes f.Finding.file f.Finding.line with
    | Some s ->
      let existing = try Stdlib.Hashtbl.find sink_map s.func_name with Stdlib.Not_found -> [] in
      Stdlib.Hashtbl.replace sink_map s.func_name (f.Finding.rule :: existing)
    | None -> ()
  ) findings;
  let all_funcs = ref Set.Poly.empty in
  Map.Poly.fold adj ~init:() ~f:(fun ~key:caller ~data:edges () ->
    all_funcs := Set.Poly.add !all_funcs caller;
    List.iter ~f:(fun (called, _, _) ->
      all_funcs := Set.Poly.add !all_funcs called
    ) edges
  );
  List.iter ~f:(fun e ->
    all_funcs := Set.Poly.add !all_funcs e.function_name
  ) entries;
  let func_file = Stdlib.Hashtbl.create 32 in
  List.iter ~f:(fun s ->
    if not (Stdlib.Hashtbl.mem func_file s.func_name) then
      Stdlib.Hashtbl.replace func_file s.func_name s.file
  ) scopes;
  List.iter ~f:(fun e ->
    if not (Stdlib.Hashtbl.mem func_file e.function_name) then
      Stdlib.Hashtbl.replace func_file e.function_name e.file
  ) entries;
  Set.Poly.to_list !all_funcs
  |> List.filter_map ~f:(fun name ->
    let file = try Stdlib.Hashtbl.find func_file name with Stdlib.Not_found -> "?" in
    let cls =
      if Stdlib.Hashtbl.mem sink_map name then
        Sink (String.concat ~sep:", " (Stdlib.Hashtbl.find sink_map name))
      else if Set.Poly.mem entry_names name then
        Entry
      else if Set.Poly.mem reachable name then
        Reachable
      else
        Dormant
    in
    Some (name, file, cls)
  )

(* ── Build ocamlgraph from adjacency ────────────────────────────────── *)

(** Build a call graph and classify nodes.
    Returns the graph, classification map, and entry count. *)
let build_call_graph (adj : call_adjacency)
    (entries : entry_point list)
    (findings : Finding.t list)
    (scopes : scope_info list)
    : CallGraph.t * (string, node_class) Stdlib.Hashtbl.t * int =
  let g = CallGraph.create ~size:64 () in
  let cls_map = Stdlib.Hashtbl.create 64 in
  (* Add edges from adjacency *)
  Map.Poly.fold adj ~init:() ~f:(fun ~key:caller ~data:edges () ->
    CallGraph.add_vertex g caller;
    List.iter ~f:(fun (called, _file, _line) ->
      CallGraph.add_edge g caller called
    ) edges
  );
  (* Add entry point vertices that may not be in adjacency *)
  List.iter ~f:(fun e ->
    CallGraph.add_vertex g e.function_name
  ) entries;
  (* Classify *)
  let classified = classify_nodes adj entries
    (reachable_from entries adj) findings scopes in
  List.iter ~f:(fun (name, _file, cls) ->
    Stdlib.Hashtbl.add cls_map name cls
  ) classified;
  (g, cls_map, List.length entries)

(* ── DOT output via ocamlgraph Graphviz ─────────────────────────────── *)

(** Color constants *)
let color_green = 0x4CAF50   (* entry *)
let color_red = 0xF44336     (* sink *)
let color_blue = 0x2196F3    (* reachable *)
let color_gray = 0x9E9E9E    (* dormant *)

(** Build the call graph data and render via ocamlgraph Dot functor.
    We inline the functor instantiation to avoid first-class module complexity. *)
let render_dot (g : CallGraph.t) (cls_map : (string, node_class) Stdlib.Hashtbl.t)
    (entry_count : int) (findings_count : int) (func_count : int) : string =
  let module D = Graph.Graphviz.Dot (struct
    include CallGraph

    let graph_attributes _ =
      [ `Rankdir `LeftToRight
      ; `Fontname "Helvetica"
      ; `Label (Stdlib.Printf.sprintf "Catseye Call Graph — %d functions, %d entry points, %d findings"
          func_count entry_count findings_count)
      ; `Fontsize 14
      ]

    let default_vertex_attributes _ =
      [ `Fontname "Helvetica"; `Fontsize 10 ]

    let vertex_name v =
      let buf = Stdlib.Bytes.create (String.length v) in
      Stdlib.String.iteri (fun i c ->
        Stdlib.Bytes.set buf i (match c with
          | '.' | ':' | '/' | ' ' | '-' -> '_'
          | c -> c)
      ) v;
      Stdlib.Bytes.to_string buf

    let vertex_attributes v =
      match Stdlib.Hashtbl.find_opt cls_map v with
      | Some Entry ->
        [ `Shape `Diamond; `Style `Bold; `Color color_green; `Fontcolor 0xFFFFFF ]
      | Some (Sink rules) ->
        [ `Shape `Box; `Style `Bold; `Color color_red; `Fontcolor 0xFFFFFF
        ; `Label (Stdlib.Printf.sprintf "%s\\n[%s]" v rules) ]
      | Some Reachable ->
        [ `Shape `Ellipse; `Style `Filled; `Color color_blue; `Fontcolor 0xFFFFFF ]
      | Some Dormant ->
        [ `Shape `Ellipse; `Style `Dashed; `Color color_gray; `Fontcolor 0xFFFFFF ]
      | None ->
        [ `Shape `Ellipse; `Style `Filled; `Color color_gray ]

    let get_subgraph _ = None
    let default_edge_attributes _ = []
    let edge_attributes e =
      let target = CallGraph.E.dst e in
      match Stdlib.Hashtbl.find_opt cls_map target with
      | Some (Sink _) -> [ `Color color_red; `Penwidth 2.0 ]
      | _ -> []
  end) in
  let buf = Stdlib.Buffer.create 4096 in
  let fmt = Stdlib.Format.formatter_of_buffer buf in
  D.fprint_graph fmt g;
  Stdlib.Format.pp_print_flush fmt ();
  Stdlib.Buffer.contents buf

(* ── Export ──────────────────────────────────────────────────────────── *)

(** Export the call graph as a DOT string. *)
let to_dot (nodes : Security_node.t list)
    (findings : Finding.t list)
    ~(custom_patterns : string list) : string =
  let scopes = build_scopes nodes in
  let adj = build_call_adjacency nodes scopes in
  let entries = detect_entry_points nodes custom_patterns in
  let g, cls_map, entry_count = build_call_graph adj entries findings scopes in
  let classified = classify_nodes adj entries
    (reachable_from entries adj) findings scopes in
  render_dot g cls_map entry_count
    (List.length findings) (List.length classified)

(** Write DOT output to a file or stdout. *)
let output_dot (nodes : Security_node.t list)
    (findings : Finding.t list)
    ~(custom_patterns : string list)
    (output_path : string) : unit =
  let content = to_dot nodes findings ~custom_patterns in
  if output_path <> "" then begin
    let oc = Stdlib.open_out output_path in
    Stdlib.output_string oc content;
    Stdlib.close_out oc;
    Stdlib.Printf.printf "Call graph written to %s\n" output_path
  end else
    Stdlib.print_string content
