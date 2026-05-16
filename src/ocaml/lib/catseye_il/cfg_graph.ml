(* lib/catseye_il/cfg_graph.ml
   OCamlgraph-based graph types for Catseye's CFG.

   Provides:
   - CfgGraph: imperative directed graph where vertices are block IDs (int)
   - Augmented CFG type: graph + Hashtbl for block content + metadata
   - Dot output via ocamlgraph's Graphviz functor

   This replaces the hand-rolled basic_block/cfg types in il_types.ml,
   giving us O(1) edge operations, standard graph traversal, and
   algorithm reuse (Fixpoint, Dominator, Components, etc.).
*)

open Il_types

(* ── Graph construction ─────────────────────────────────────────────── *)

(** Directed graph with concrete int vertices.
    Vertices are block IDs (int). Edges represent control flow. *)
module G = Graph.Imperative.Digraph.Concrete (struct
  type t = int
  let compare = compare
  let hash = Hashtbl.hash
  let equal = ( = )
end)

(** Augmented CFG: ocamlgraph + block content + metadata.
    The graph stores the topology (vertices + edges).
    The Hashtbl stores the IL nodes for each block. *)
type t = {
  graph : G.t;
  mutable entry : G.V.t;                          (* entry block ID *)
  blocks : (int, il_node list) Hashtbl.t;  (* block_id -> nodes *)
  fn_name : string;
  fn_params : string list;
  fn_pos : pos;
  block_count : int ref;                   (* for bounds checking *)
}

(** Create an empty augmented CFG. *)
let create (fn : il_function) : t = {
  graph = G.create ~size:16 ();
  entry = 0;
  blocks = Hashtbl.create 16;
  fn_name = fn.fn_name;
  fn_params = fn.fn_params;
  fn_pos = fn.fn_pos;
  block_count = ref 0;
}

(** Add a basic block (vertex) to the graph with a given ID.
    Returns the block ID. *)
let add_block (cfg : t) (id : int) (nodes : il_node list) : int =
  incr cfg.block_count;
  G.add_vertex cfg.graph id;
  Hashtbl.add cfg.blocks id nodes;
  id

(** Add a control flow edge between two blocks. *)
let add_edge (cfg : t) (src : int) (dst : int) : unit =
  G.add_edge cfg.graph src dst

(** Set the entry block. *)
let set_entry (cfg : t) (id : int) : unit =
  cfg.entry <- id

(** Get the IL nodes for a block. *)
let block_nodes (cfg : t) (id : int) : il_node list =
  match Hashtbl.find_opt cfg.blocks id with
  | Some nodes -> nodes
  | None -> []

(** Iterate over successors of a block. *)
let iter_succ (cfg : t) (f : int -> unit) (id : int) : unit =
  G.iter_succ f cfg.graph id

(** Get all successors as a list. *)
let succ_list (cfg : t) (id : int) : int list =
  let succs = ref [] in
  G.iter_succ (fun v -> succs := v :: !succs) cfg.graph id;
  List.rev !succs

(** Iterate over all vertices (block IDs). *)
let iter_vertices (cfg : t) (f : int -> unit) : unit =
  G.iter_vertex f cfg.graph

(** Number of vertices. *)
let v_count (cfg : t) : int =
  G.nb_vertex cfg.graph

(** Check if an edge exists. *)
let has_edge (cfg : t) (src : int) (dst : int) : bool =
  G.mem_edge cfg.graph src dst

(* ── DOT output via ocamlgraph Graphviz ─────────────────────────────── *)

(** Graphviz renderer for the CFG. *)
module CfgDot = Graph.Graphviz.Dot (struct
  include G

  let graph_attributes _ =
    [ `Rankdir `LeftToRight
    ; `Fontname "Helvetica"
    ; `Label "CFG"
    ; `Fontsize 14
    ]

  let default_vertex_attributes _ =
    [ `Shape `Box
    ; `Style `Filled
    ; `Fontname "Monospace"
    ; `Fontsize 10
    ]

  let vertex_name v = Printf.sprintf "b%d" v

  let vertex_attributes _v =
    [ `Color 0x2196F3
    ; `Fillcolor 0xE3F2FD
    ]

  let get_subgraph _ = None

  let default_edge_attributes _ =
    [ `Color 0x666666
    ]

  let edge_attributes _e =
    []
end)

(** Render the CFG as a DOT string. *)
let to_dot (cfg : t) : string =
  let buf = Buffer.create 4096 in
  let fmt = Format.formatter_of_buffer buf in
  CfgDot.fprint_graph fmt cfg.graph;
  Format.pp_print_flush fmt ();
  Buffer.contents buf
