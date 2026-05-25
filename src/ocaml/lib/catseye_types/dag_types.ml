(* lib/catseye_types/dag_types.ml
   Vulnerability DAG types — represent multi-path taint flows. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

(** A node in the vulnerability DAG. *)
type node_id = string

type dag_node = {
  id : node_id;
  label : string;
  node_type : [ `Source | `Propagator | `Sink | `Sanitizer ];
  file : string;
  line : int;
}

(** An edge in the DAG: from → to with optional label. *)
type dag_edge = {
  src : node_id;
  dst : node_id;
  label : string;
}

(** A complete vulnerability DAG for one finding. *)
type vulnerability_dag = {
  nodes : dag_node list;
  edges : dag_edge list;
  entry_points : node_id list;
  exit_point : node_id;
}
