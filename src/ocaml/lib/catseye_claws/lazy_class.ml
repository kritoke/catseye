(* lib/catseye_claws/lazy_class.ml *)

(** LazyClass detector.

    A class or module with fewer than 3 methods is likely a Lazy Class —
    it isn't doing enough to warrant its own type. Fowler's smell.

    https://martinfowler.com/bliki/LazyClass.html

    exemptions:
    - Struct/Record types (Crystal idioms with attribute accessors)
    - Configuration classes in /config/ or *_config.cr
    - Single-method classes with only getters/properties (data containers)
    - Classes named "Constants", "Defaults", etc.
*)

open Catseye_types

(* ── Helpers ──────────────────────────────────────────────────────── *)

(** Check if a string contains a substring *)
let contains (str : string) (sub : string) : bool =
  let slen = String.length str in
  let slen_sub = String.length sub in
  if slen_sub > slen then false
  else
    let rec check i =
      if i > slen - slen_sub then false
      else if String.sub str i slen_sub = sub then true
      else check (i + 1)
    in
    check 0

(** Check if file is a config/structure file *)
let is_config_file (file : string) : bool =
  let lower = String.lowercase_ascii file in
  contains lower "/config/" ||
  contains lower "_config.cr" ||
  contains lower "/settings/" ||
  contains lower "/structures/" ||
  contains lower "/types/"

(** Check if a class name suggests it's a data/struct type *)
let is_data_class_name (name : string) : bool =
  let lower = String.lowercase_ascii name in
  contains lower "struct" ||
  contains lower "record" ||
  contains lower "config" ||
  contains lower "settings" ||
  contains lower "constants" ||
  contains lower "defaults" ||
  contains lower "options" ||
  contains lower "params"

(** Check if a class is a data-only class (only has getters/properties) *)
let is_data_only_class (methods : Scope.scope list) : bool =
  List.for_all (fun (s : Scope.scope) ->
    let name = String.lowercase_ascii s.def.Security_node.name in
    contains name "getter" ||
    contains name "property" ||
    contains name "setter" ||
    contains name "initialize" ||
    contains name "new"
  ) methods

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.lazy_class_enabled then [] else
    let threshold = config.lazy_class_method_threshold in
    let class_scopes = Scope.build_class_scopes nodes in
    List.filter_map (fun (cs : Scope.class_scope) ->
      let file = cs.class_node.Security_node.file in
      let name = cs.class_node.Security_node.name in
      let method_count = List.length cs.methods in

      (* Exemptions *)
      if is_config_file file then None
      else if is_data_class_name name then None
      else if method_count = 1 && is_data_only_class cs.methods then None
      else if method_count > 0 && method_count < threshold then
        Some {
          Finding.rule = "LazyClass";
          severity = "Medium";
          file = file;
          line = cs.class_node.Security_node.line;
          message = Printf.sprintf
            "Class '%s' has only %d method(s) (threshold: %d). \
             Consider whether it deserves its own type or can be absorbed elsewhere."
            name method_count threshold;
          flow = [ {
            Finding.file = file;
            line = cs.class_node.Security_node.line;
            message = Printf.sprintf "Definition of '%s' (%d methods)"
              name method_count;
          } ];
          language = cs.class_node.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
    ) class_scopes