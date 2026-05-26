(* lib/catseye_types/extractor_cmds.ml
   Shared extractor command configuration.
   
   This module provides a simple, dependency-free record for Crystal
   extractor commands. It lives at the types layer so all modules
   (ast, engine, cli) can share it without circular dependencies.
   
   Engine integration: catseye_engine.Extractor_registry can convert
   to this type via Extractor_registry.to_cmds.
*)

(** Commands for Crystal extractors *)
type t = {
  flat : string;  (* Flat extractor command *)
  hier : string;  (* Hierarchical extractor command *)
}

(** Default commands using crystal run *)
let default = {
  flat = "crystal run src/extractor/extractor.cr --";
  hier = "crystal run src/extractor/hierarchical_extractor.cr --";
}