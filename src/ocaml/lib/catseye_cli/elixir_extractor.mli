(* lib/catseye_cli/elixir_extractor.mli *)
(* OCaml interface to the Elixir AST extractor *)

val extract_with_data : string -> (Catseye_types.Finding.t list * Yojson.Safe.t list)
val extract : string -> Catseye_types.Finding.t list
val extract_file : string -> Catseye_types.Finding.t list