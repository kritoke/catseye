(* src/ocaml/lib/catseye_ast/gleam_mapper.ml
   Bridge from tree-sitter Gleam XML output to CatseyeAST.t
   
   Part of the JSON Bridge - tree-sitter XML → CatseyeAST.t
*)

open Types
open Error

(* Note: Full tree-sitter integration will be added when generic_ast
   is properly integrated. For now, this module provides the conversion
   interface that will be used by the CLI integration. *)

(** Stub: Parse a Gleam file using tree-sitter *)
let parse_file ~(path : string) : (t, parse_error) result =
  Error (make_error ~file:path 
    ~message:"Gleam tree-sitter parsing requires CATSEYE_GLEAM grammar path")