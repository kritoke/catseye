(* lib/catseye_claws/shotgun_surgery.ml *)

(** Shotgun Surgery detector.

    Shotgun Surgery is a code smell where a single change requires modifying
    many different classes, indicating poor responsibility encapsulation.
    
    https://martinfowler.com/bliki/ShotgunSurgery.html
*)

open Base

(* String comparison shadows *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_types

(* ── Config thresholds ─────────────────────────────────────────────── *)

let default_envy_threshold = 5

(* Exempt patterns for helper/facade classes and logging APIs *)
let exempt_class_patterns = [
  "Dispatcher";
  "Router";
  "Facade";
  "Adapter";
  "Proxy";
  "Builder";
  "Log";
  "Logger";
  "Time";
  "StateStore";
]

(* ── Helpers ───────────────────────────────────────────────────────── *)

let contains = Scope.contains

let is_exempt_class (class_name : string) : bool =
  Stdlib.List.exists (fun pattern -> contains class_name pattern) exempt_class_patterns

(* Extract class name from a call like "Config.get" -> "Config" or "@logger.info" -> "Logger" *)
let rec extract_class_name (call_name : string) : string option =
  if contains call_name "." then
    (try
      let receiver = Stdlib.String.sub call_name 0 (Stdlib.String.index call_name '.') in
      let class_name = 
        if Stdlib.String.length receiver > 0 && Stdlib.String.get receiver 0 = '@' then
          Stdlib.String.sub receiver 1 (Stdlib.String.length receiver - 1)
        else
          receiver
      in
      if Stdlib.String.length class_name > 0 && Stdlib.String.get class_name 0 = '$' then None
      else if is_common_local_var class_name then None
      else if Stdlib.String.length class_name >= 3 && Stdlib.Char.compare (Stdlib.String.get class_name 0) 'A' >= 0 && Stdlib.Char.compare (Stdlib.String.get class_name 0) 'Z' <= 0 && not (contains class_name "_") then Some class_name
      else None
    with Stdlib.Not_found -> None)
  else
    None

and is_common_local_var (name : string) : bool =
  let lower = Stdlib.String.lowercase_ascii name in
  Stdlib.List.exists (fun p -> lower = p) [
    "response"; "result"; "data"; "value"; "item"; "node"; "map";
    "cmd"; "request"; "hash"; "array"; "list"; "set"; "uri"; "url";
    "err"; "error"; "entries"; "links"; "parser"; "builder";
    "logger"; "config"; "client"; "store"; "validator"; "reader"; "writer"; "factory";
    "cache"; "connection"; "session"; "user"; "message"; "event"; "handler";
    "service"; "repo"; "repository"; "adapter"; "resolver"; "fetcher";
    "success"; "failure"; "content"; "body"; "header"; "headers";
    "title"; "author"; "url"; "categories"; "attachments";
  ]

(* ── Feature Envy Detection ───────────────────────────────────────── *)

type envy_target = {
  receiver : string;
  call_count : int;
  locations : (string * int) list;
}

let detect_feature_envy (nodes : Security_node.t list) : envy_target list =
  let receiver_calls = Stdlib.Hashtbl.create 16 in
  
  Stdlib.List.iter (fun n ->
    if n.Security_node.node_type = Security_node.Call then
      let name = n.Security_node.name in
      let extracted = extract_class_name name in
      (match extracted with
       | Some r ->
           if Stdlib.String.length r >= 3 then
             (try
               let _ = Stdlib.String.index name '.' in
               let key = n.Security_node.file ^ "|" ^ r in
               let existing = try Stdlib.Hashtbl.find receiver_calls key with Stdlib.Not_found -> ([], 0) in
               let (locs, count) = existing in
               let new_locs = (n.Security_node.file, n.Security_node.line) :: locs in
               Stdlib.Hashtbl.replace receiver_calls key (new_locs, count + 1)
             with Stdlib.Not_found -> ())
       | None -> ())
  ) nodes;

  let result = Stdlib.ref [] in
  Stdlib.Hashtbl.iter (fun key (locs, count) ->
    if count >= default_envy_threshold then
      match Stdlib.String.split_on_char '|' key with
      | [file; receiver] ->
          let has_class = Stdlib.List.exists (fun n ->
            n.Security_node.node_type = Security_node.Class 
            && n.Security_node.file = file
          ) nodes in
          if has_class && not (is_exempt_class receiver) then
            result := { receiver; call_count = count; locations = locs } :: !result
      | _ -> ()
  ) receiver_calls;
  
  !result

(* ── Analyzer ─────────────────────────────────────────────────────── *)

let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.large_class_enabled then [] else
    let feature_envy = detect_feature_envy nodes in
    Stdlib.List.filter_map (fun target ->
      let file = 
        match target.locations with
        | [] -> ""
        | (f, _) :: _ -> f
      in
      let line = 
        match target.locations with
        | [] -> 1
        | (_, l) :: _ -> l
      in
      Some {
        Finding.rule = "ShotgunSurgery";
        severity = "Medium";
        file;
        line;
        message = Stdlib.Printf.sprintf
          "Feature Envy: '%s' calls '%s' %d times. This behavior may belong in '%s', not here. Consider moving these methods or using composition/refactoring."
          file target.receiver target.call_count target.receiver;
        flow = [ {
          Finding.file;
          line;
          message = Stdlib.Printf.sprintf "File '%s' makes %d calls to '%s'" file target.call_count target.receiver;
        } ];
        language = "crystal";
        dependency = None;
        reachability = None; suggestion = None;
      }
    ) feature_envy