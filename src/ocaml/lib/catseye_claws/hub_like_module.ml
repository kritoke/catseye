(* lib/catseye_claws/hub_like_module.ml *)

(** Hub-like Module detector.

    A Hub-like Module is a class that depends on too many other classes,
    creating high coupling and violating Single Responsibility Principle.
    
    Detection heuristic:
    - Count unique class types referenced (instantiated, typed, or called)
    - If count exceeds threshold, report as smell

    https://martinfowler.com/bliki/HubLikeModule.html
*)

open Base

(* String comparison shadow *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_types

(* ── Config thresholds ─────────────────────────────────────────────── *)

let default_hub_threshold_warning = 12
let default_hub_threshold_critical = 20

(* Exempt classes that are typically hubs by design *)
let exempt_class_patterns = [
  "Dispatcher";
  "Router";
  "Container";
  "Bootstrap";
  "Initializer";
  "Factory";
]

(* ── Helpers ───────────────────────────────────────────────────────── *)

let contains (str : string) (sub : string) : bool =
  let slen = Stdlib.String.length str in
  let slen_sub = Stdlib.String.length sub in
  if slen_sub > slen then false
  else
    let rec check i =
      if i > slen - slen_sub then false
      else if Stdlib.String.sub str i slen_sub = sub then true
      else check (i + 1)
    in
    check 0

let is_exempt_class (class_name : string) : bool =
  Stdlib.List.exists (fun pattern -> contains class_name pattern) exempt_class_patterns

(* Extract class name from a type reference like "HTTP::Client" → "HTTP::Client" *)
let extract_class_name (type_ref : string) : string =
  match Stdlib.String.index_opt type_ref '<' with
  | Some idx -> Stdlib.String.sub type_ref 0 idx
  | None -> 
    (match Stdlib.String.index_opt type_ref '|' with
     | Some idx -> Stdlib.String.sub type_ref 0 idx
     | None -> type_ref)

(* Normalize class name for comparison *)
let normalize_class_name (name : string) : string =
  let trimmed = Stdlib.String.trim name in
  if trimmed = "" || trimmed = "Nil" || trimmed = "Void" then ""
  else if Stdlib.List.exists (fun p -> trimmed = p) ["String"; "Int32"; "Int64"; "Float"; "Bool"; "Number"; "Array"; "Hash"; "Symbol"; "Object"]
  then ""
  else trimmed

(* ── Dependency counting ───────────────────────────────────────────── *)

let count_unique_dependencies (nodes : Security_node.t list) 
    (class_file : string) : int =
  let deps = Stdlib.Hashtbl.create 32 in
  
  let add_dep name =
    if contains name "::" then
      let normalized = normalize_class_name name in
      if normalized <> "" then Stdlib.Hashtbl.replace deps normalized true
  in
  
  Stdlib.List.iter (fun node ->
    if node.Security_node.file = class_file then
      if node.Security_node.node_type = Security_node.Call then
        let name = node.Security_node.name in
        if contains name "." then
          (try
            let dot_idx = Stdlib.String.index name '.' in
            let receiver = Stdlib.String.sub name 0 dot_idx in
            add_dep receiver
          with Stdlib.Not_found -> ())
        else
          add_dep name
      ;
      if node.Security_node.node_type = Security_node.Assign then
        Stdlib.List.iter (fun arg ->
          if arg.Security_node.arg_type = Security_node.ArgCall then
            add_dep arg.Security_node.value
        ) node.Security_node.args
  ) nodes;
  
  Stdlib.Hashtbl.length deps

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.large_class_enabled then [] else
    let class_scopes = Scope.build_class_scopes nodes in
    Stdlib.List.filter_map (fun (cs : Scope.class_scope) ->
      let class_name = cs.class_node.Security_node.name in
      let file = cs.class_node.Security_node.file in
      let line = cs.class_node.Security_node.line in
      
      if is_exempt_class class_name then None
      else begin
        let dep_count = count_unique_dependencies nodes file in
        
        if dep_count >= default_hub_threshold_critical then
          Some {
            Finding.rule = "HubLikeModule";
            severity = "High";
            file;
            line;
            message = Stdlib.Printf.sprintf
              "Class '%s' is a Hub-like Module: references %d different classes. \
               This indicates high coupling - consider extracting responsibilities into separate modules."
              class_name dep_count;
            flow = [ {
              Finding.file;
              line;
              message = Stdlib.Printf.sprintf "Definition of '%s' (%d class dependencies)"
                class_name dep_count;
            } ];
            language = cs.class_node.Security_node.language;
            dependency = None;
            reachability = None; suggestion = None;
          }
        else if dep_count >= default_hub_threshold_warning then
          Some {
            Finding.rule = "HubLikeModule";
            severity = "Medium";
            file;
            line;
            message = Stdlib.Printf.sprintf
              "Class '%s' has many dependencies (%d classes). \
               Consider if this indicates too much coupling."
              class_name dep_count;
            flow = [ {
              Finding.file;
              line;
              message = Stdlib.Printf.sprintf "Definition of '%s' (%d class dependencies)"
                class_name dep_count;
            } ];
            language = cs.class_node.Security_node.language;
            dependency = None;
            reachability = None; suggestion = None;
          }
        else None
      end
    ) class_scopes