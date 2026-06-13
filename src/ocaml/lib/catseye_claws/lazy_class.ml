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

open Base

(* String comparison shadow *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_types

(* ── Helpers ──────────────────────────────────────────────────────── *)

(* contains inherited from Scope *)
let contains = Scope.contains

(** Check if file is a config/structure file *)
let is_config_file (file : string) : bool =
  let lower = Stdlib.String.lowercase_ascii file in
  contains lower "/config/" ||
  contains lower "_config.cr" ||
  contains lower "/settings/" ||
  contains lower "/structures/" ||
  contains lower "/types/" ||
  contains lower "/dtos/" ||
  contains lower "/entities/" ||
  contains lower "/models/"

(** Check if a class name suggests it's a data/struct type *)
let is_data_class_name (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  contains lower "struct" ||
  contains lower "record" ||
  contains lower "config" ||
  contains lower "settings" ||
  contains lower "constants" ||
  contains lower "defaults" ||
  contains lower "options" ||
  contains lower "params" ||
  contains lower "dto" ||
  contains lower "entity" ||
  contains lower "model"

(** Check if a class name suggests it's a delegate/filter class. *)
let is_delegate_class_name (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  contains lower "filter" ||
  contains lower "parser" ||
  contains lower "formatter" ||
  contains lower "renderer" ||
  contains lower "converter" ||
  contains lower "adapter" ||
  contains lower "handler" ||
  contains lower "processor" ||
  contains lower "serializer" ||
  contains lower "deserializer" ||
  contains lower "validator" ||
  contains lower "builder" ||
  contains lower "generator" ||
  (contains lower "to" && 
   (contains lower "string" || contains lower "html" || contains lower "json" || contains lower "xml")) ||
  contains lower "ify" ||
  contains lower "escape" ||
  contains lower "sanitize" ||
  contains lower "exp" ||
  (contains lower "url" || contains lower "path" || contains lower "link" || contains lower "relative" || contains lower "absolute") ||
  contains lower "localize" ||
  contains lower "slugify" ||
  (contains lower "strip" || contains lower "truncate" || contains lower "split" || 
   contains lower "slice" || contains lower "escape" || contains lower "normalize" ||
   contains lower "newline" || contains lower "index" || contains lower "whitespace" ||
   contains lower "times" || contains lower "minus" || contains lower "striptags" || contains lower "xml" ||
   contains lower "contains" || contains lower "replace" || contains lower "remove" || contains lower "append" ||
   contains lower "prepend" || contains lower "first" || contains lower "last" || contains lower "sort" ||
   contains lower "join" || contains lower "compact" || contains lower "uniq" || contains lower "size" ||
   contains lower "default" || contains lower "floor" || contains lower "ceil" || contains lower "round" ||
   contains lower "sum" || contains lower "avg" || contains lower "abs" ||
   contains lower "date" || contains lower "time" || contains lower "where" || contains lower "group" ||
   contains lower "any" || contains lower "all" || contains lower "none" || contains lower "include" ||
   contains lower "highlight" || contains lower "markdown" || contains lower "textilize") &&
  not (contains lower "class") &&
  Stdlib.String.length name > 4

(** Check if a class name is an Athena/web framework controller. *)
let is_controller_class (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  contains lower "controller" ||
  contains lower "endpoint" ||
  contains lower "component"

(** Check if a class is a data-only class (only has getters/properties) *)
let is_data_only_class (methods : Scope.scope list) : bool =
  Stdlib.List.for_all (fun (s : Scope.scope) ->
    let name = Stdlib.String.lowercase_ascii s.def.Security_node.name in
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
    Stdlib.List.filter_map (fun (cs : Scope.class_scope) ->
      let file = cs.class_node.Security_node.file in
      let name = cs.class_node.Security_node.name in
      let method_count = Stdlib.List.length cs.methods in

      (* Exemptions *)
      if is_config_file file then None
      else if is_data_class_name name then None
      else if is_controller_class name then None
      else if is_delegate_class_name name && method_count <= 5 then None
      else if method_count = 1 && is_data_only_class cs.methods then None
      else if method_count > 0 && method_count < threshold then
        Some {
          Finding.rule = "LazyClass";
          severity = "Medium";
          file = file;
          line = cs.class_node.Security_node.line;
          message = Stdlib.Printf.sprintf
            "Class '%s' has only %d method(s) (threshold: %d). \
             Consider whether it deserves its own type or can be absorbed elsewhere."
            name method_count threshold;
          flow = [ {
            Finding.file = file;
            line = cs.class_node.Security_node.line;
            message = Stdlib.Printf.sprintf "Definition of '%s' (%d methods)"
              name method_count;
          } ];
          language = cs.class_node.Security_node.language;
          dependency = None;
          reachability = None; suggestion = None;
        }
      else None
    ) class_scopes