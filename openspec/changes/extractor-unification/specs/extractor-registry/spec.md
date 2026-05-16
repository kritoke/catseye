# Extractor Registry Spec

## Type signatures

```ocaml
(* extractor_registry.mli *)

type t

(** Create a registry by resolving both extractors.
    Called once at startup from args.ml. *)
val create : ?flat_override:string -> ?hier_override:string -> unit -> t

(** Command for the flat extractor (Security_node.t JSON) *)
val flat_cmd : t -> string

(** Command for the hierarchical extractor (CatseyeAST JSON) *)
val hier_cmd : t -> string

(** Whether the flat extractor is a pre-compiled binary *)
val flat_is_compiled : t -> bool

(** Whether the hierarchical extractor is a pre-compiled binary *)
val hier_is_compiled : t -> bool

(** Extract a single file using the flat extractor.
    Spawns a subprocess, returns JSON string. *)
val extract_flat : t -> path:string -> string option

(** Extract a single file using the hierarchical extractor.
    Spawns a subprocess, returns JSON string. *)
val extract_hier : t -> path:string -> string option

(** Create a worker pool for batch flat extraction.
    Only valid when flat_is_compiled = true (--serve mode).
    Caller must call shutdown_pool when done. *)
val create_pool : t -> num_workers:int -> Worker_pool.t

(** Shutdown a previously created pool. *)
val shutdown_pool : Worker_pool.t -> unit
```

## Resolution algorithm

```
resolve(name):
  1. If env var override exists → use it (may be "crystal run ..." or binary path)
  2. Pre-compiled next to Sys.executable_name → use if exists
  3. Search upward from CWD for bin/<name> → use if exists
  4. Global install layout → use if exists
  5. Source file relative to CWD → "crystal run <source> --"
  6. Error / empty string
```

## Integration points

### args.ml (startup)

```ocaml
let registry = Extractor_registry.create
  ~flat_override:(try Some (Sys.getenv "CATSEYE_CRYSTAL_EXTRACTOR") with Not_found -> None)
  ~hier_override:(try Some (Sys.getenv "CATSEYE_CRYSTAL_HIERARCHICAL") with Not_found -> None)
  ()
in
{ cfg with extractor_registry = registry }
```

### orchestrator.ml (Claws path)

```ocaml
(* Before: 53 separate subprocess spawns *)
let ast_modules = List.filter_map (fun src ->
  match Catseye_ast.Parse.parse_file ~path:src.path with
  | Ok mod_ -> Some mod_
  | Error _ -> None
) sources in

(* After: use registry for extraction, parse JSON in-process *)
let ast_modules = List.filter_map (fun src ->
  match Extractor_registry.extract_hier config.extractor_registry ~path:src.path with
  | Some json -> Some (Catseye_ast.Crystal_hierarchical_mapper.parse_json json)
  | None -> None
) sources in
```

### crystal_mapper.ml / crystal_hierarchical_mapper.ml

```ocaml
(* Before: self-resolving *)
let parse_file ~(path:string) : (t, parse_error) result =
  let extractor_cmd = resolve_hierarchical_extractor () in
  ...

(* After: accept cmd parameter, no resolution *)
let parse_file ~(extractor_cmd:string) ~(path:string) : (t, parse_error) result =
  let cmd = Printf.sprintf "%s '%s' 2>/dev/null" extractor_cmd path in
  ...

(** Parse from pre-fetched JSON (for batch extraction via pool) *)
val parse_json : string -> (t, parse_error) result
```
