(* src/ocaml/lib/catseye_ast/parse.ml
   Unified parsing interface - JSON Bridge for Gleam and Crystal
*)

open Types
open Error

(** Language from file extension *)
let lang_of_extension path =
  if Filename.check_suffix path ".gleam" then Some Gleam
  else if Filename.check_suffix path ".cr" then Some Crystal
  else None

(** Parse a file, inferring language from extension *)
let parse_file ~(path : string) : (t, parse_error) result =
  match lang_of_extension path with
  | None -> Error (make_error ~file:path ~message:"Unknown file type")
  | Some lang ->
      match lang with
      | Gleam -> Error (make_error ~file:path ~message:"Gleam parsing not yet implemented")
      | Crystal -> Error (make_error ~file:path ~message:"Crystal parsing not yet implemented")