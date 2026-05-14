(* src/ocaml/lib/catseye_ast/crystal_mapper.ml
   Bridge from Crystal Security_node JSON to CatseyeAST.t
   
   Part of the JSON Bridge - Crystal extractor JSON → CatseyeAST.t
*)

open Types
open Error

(* Note: Full Crystal extractor integration will be added when
   Security_node JSON format is properly defined. For now, this
   module provides the conversion interface. *)

(** Stub: Parse a Crystal file using the extractor *)
let parse_file ~(path : string) : (t, parse_error) result =
  Error (make_error ~file:path 
    ~message:"Crystal parsing requires CATSEYE_CRYSTAL_EXTRACTOR env var")