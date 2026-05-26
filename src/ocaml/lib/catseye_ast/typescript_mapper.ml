(* lib/catseye_ast/typescript_mapper.ml
   Bridge from tree-sitter TypeScript XML output to CatseyeAST.t.
   
   Extends Javascript_mapper for TypeScript-specific syntax
   (type annotations, interfaces, enums, decorators, generics).
 *)

module PE = Error

open Base
open Types
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

include Javascript_mapper

(** Parse a TypeScript file (.ts, .tsx). *)
let parse_file ~(path : string) : (t, PE.parse_error) Result.t =
  match resolve_ts_grammar () with
  | None ->
    Error (PE.make_error ~file:path ~message:"TypeScript tree-sitter grammar not found. Set TREE_SITTER_TYPESCRIPT_GRAMMAR or install tree-sitter-typescript.")
  | Some grammar ->
    parse_with_grammar ~grammar ~lang:"typescript" ~path
