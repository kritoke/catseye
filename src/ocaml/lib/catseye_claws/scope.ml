(* lib/catseye_claws/scope.ml *)

(** Shared scope building utilities.

    Both complexity.ml and extra_smells.ml need to build function scopes
    (Def node + its body). This module centralizes that logic.
*)

open Base

(* String/int comparison shadows *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_types

(* ── Helpers ───────────────────────────────────────────────────────── *)

(** Find substring [needle] in [haystack], returning start index or -1. *)
let find_substring (haystack : string) (needle : string) : int =
  let hlen = Stdlib.String.length haystack in
  let nlen = Stdlib.String.length needle in
  if nlen > hlen then -1
  else begin
    let result = Stdlib.ref (-1) in
    (try
      for i = 0 to hlen - nlen do
        if Stdlib.String.sub haystack i nlen = needle then begin
          result := i; raise Stdlib.Exit
        end
      done
    with Stdlib.Exit -> ());
    !result
  end

(* ── Types ──────────────────────────────────────────────────────────── *)

type scope = {
  def : Security_node.t;
  body : Security_node.t list;
}

(* ── Class scope ───────────────────────────────────────────────────── *)

type class_scope = {
  class_node : Security_node.t;
  methods : scope list;
  loc : int;
}

(* ── Scope building ────────────────────────────────────────────────── *)

(** Build function scopes from a flat node list, grouped by file. *)
let build_scopes (nodes : Security_node.t list) : scope list =
  (* Group by file *)
  let by_file = Stdlib.Hashtbl.create 16 in
  Stdlib.List.iter (fun (n : Security_node.t) ->
    let existing = try Stdlib.Hashtbl.find by_file n.Security_node.file with Stdlib.Not_found -> [] in
    Stdlib.Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  (* For each file, find Def nodes and their bodies *)
  let scopes = Stdlib.ref [] in
  Stdlib.Hashtbl.iter (fun _file file_nodes ->
    let sorted = Stdlib.List.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
    let defs = Stdlib.List.filter (fun n -> n.Security_node.node_type = Security_node.Def) sorted in
    Stdlib.List.iteri (fun i (def : Security_node.t) ->
      let start_line = def.Security_node.line in
      let end_line =
        if i + 1 < Stdlib.List.length defs then
          (Stdlib.List.nth defs (i + 1)).Security_node.line
        else Stdlib.max_int
      in
      let body = Stdlib.List.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type <> Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in
      scopes := { def; body } :: !scopes
    ) defs
  ) by_file;
  Stdlib.List.rev !scopes

(* ── Class scope building ──────────────────────────────────────────── *)

(** Build class scopes from a flat node list. *)
let build_class_scopes (nodes : Security_node.t list) : class_scope list =
  (* Group nodes by file *)
  let by_file = Stdlib.Hashtbl.create 16 in
  Stdlib.List.iter (fun (n : Security_node.t) ->
    let existing = try Stdlib.Hashtbl.find by_file n.Security_node.file with Stdlib.Not_found -> [] in
    Stdlib.Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  let class_scopes = Stdlib.ref [] in
  Stdlib.Hashtbl.iter (fun _file file_nodes ->
    let sorted = Stdlib.List.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
    let type_defs = Stdlib.List.filter (fun n ->
      Stdlib.List.mem n.Security_node.node_type
        [Security_node.Class; Security_node.Module; Security_node.Enum]
    ) sorted in
    Stdlib.List.iteri (fun i (td : Security_node.t) ->
      let start_line = td.Security_node.line in
      let end_line =
        if i + 1 < Stdlib.List.length type_defs then
          (Stdlib.List.nth type_defs (i + 1)).Security_node.line
        else 1000000
      in
      let methods_in_class = Stdlib.List.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in
      let method_scopes = Stdlib.List.map (fun (def : Security_node.t) ->
        let body = Stdlib.List.filter (fun (n : Security_node.t) ->
          n.Security_node.node_type <> Security_node.Def
          && n.Security_node.line >= def.Security_node.line
          && n.Security_node.line < end_line
          && n.Security_node.line >= start_line
        ) sorted in
        { def; body }
      ) methods_in_class in
      let loc =
        let real_end =
          if end_line >= 1000000 then
            let max_line = Stdlib.List.fold_left (fun acc (n : Security_node.t) ->
              Stdlib.max acc n.Security_node.line
            ) start_line sorted in
            max_line + 1
          else end_line
        in
        real_end - start_line
      in
      class_scopes := { class_node = td; methods = method_scopes; loc } :: !class_scopes
    ) type_defs
  ) by_file;
  Stdlib.List.rev !class_scopes

(* ── Helpers ───────────────────────────────────────────────────────── *)

(** Get the class/module/enum containing a node, by file and line range. *)
let find_enclosing_class (nodes : Security_node.t list) (file : string) (line : int)
    : Security_node.t option =
  let file_nodes = Stdlib.List.filter (fun n -> n.Security_node.file = file) nodes in
  let sorted = Stdlib.List.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
  let type_defs = Stdlib.List.filter (fun n ->
    Stdlib.List.mem n.Security_node.node_type
      [Security_node.Class; Security_node.Module; Security_node.Enum]
  ) sorted in
  let rec find = function
    | [] -> None
    | [td] -> if td.Security_node.line <= line then Some td else None
    | td :: rest ->
      if td.Security_node.line <= line then
        match rest with
        | [] -> Some td
        | next :: _ -> if next.Security_node.line > line then Some td else find rest
      else find rest
  in find type_defs