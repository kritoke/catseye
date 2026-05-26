(* lib/catseye_ast/plugin_registry.ml
   Plugin registry — maps file extensions and language names to plugins.

   The registry is created once at startup with the available plugins
   and used by discovery, parsing, and extraction throughout the pipeline.
 *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

module Lp = Language_plugin

type registry = {
  by_name : (string, Lp.t) Stdlib.Hashtbl.t;
  by_ext : (string, Lp.t) Stdlib.Hashtbl.t;
}

(** Create an empty registry. *)
let create () : registry = {
  by_name = Stdlib.Hashtbl.create 8;
  by_ext = Stdlib.Hashtbl.create 16;
}

(** Register a plugin. Raises Invalid_argument on duplicate name or extension. *)
let register (r : registry) (plugin : Lp.t) : unit =
  if Stdlib.Hashtbl.mem r.by_name plugin.Lp.name then
    invalid_arg (Stdlib.Printf.sprintf "Plugin '%s' already registered" plugin.Lp.name);
  List.iter ~f:(fun ext ->
    if Stdlib.Hashtbl.mem r.by_ext ext then
      invalid_arg (Stdlib.Printf.sprintf "Extension '%s' already claimed by another plugin" ext);
    Stdlib.Hashtbl.add r.by_ext ext plugin
  ) plugin.Lp.extensions;
  Stdlib.Hashtbl.add r.by_name plugin.Lp.name plugin

(** Look up a plugin by file extension (e.g. ".cr"). *)
let for_extension (r : registry) (ext : string) : Lp.t option =
  Stdlib.Hashtbl.find_opt r.by_ext ext

(** Look up a plugin by name (e.g. "crystal"). *)
let for_name (r : registry) (name : string) : Lp.t option =
  Stdlib.Hashtbl.find_opt r.by_name name

(** List all registered language names. *)
let languages (r : registry) : string list =
  Stdlib.Hashtbl.fold (fun name _ acc -> name :: acc) r.by_name []

(** Check if a language is available. *)
let available (r : registry) (name : string) : bool =
  Stdlib.Hashtbl.mem r.by_name name

(** All extensions across all plugins. *)
let all_extensions (r : registry) : string list =
  Stdlib.Hashtbl.fold (fun _ plugin acc ->
    plugin.Lp.extensions @ acc
  ) r.by_name []

(** All manifest files across all plugins. *)
let all_manifests (r : registry) : string list =
  Stdlib.Hashtbl.fold (fun _ plugin acc ->
    plugin.Lp.manifest_files @ acc
  ) r.by_name []

(** Get language name for a file path, if any plugin handles it. *)
let lang_of_path (r : registry) (path : string) : string option =
  let rec try_exts = function
    | [] -> None
    | ext :: rest ->
      if Stdlib.Filename.check_suffix path ext then begin
        match for_extension r ext with
        | Some p -> Some p.Lp.name
        | None -> None
      end else try_exts rest
  in
  try_exts (all_extensions r)