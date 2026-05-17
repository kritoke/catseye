(* lib/catseye_claws/scope.ml *)

(** Shared scope building utilities.

    Both complexity.ml and extra_smells.ml need to build function scopes
    (Def node + its body). This module centralizes that logic.
*)

open Catseye_types

(* ── Helpers ───────────────────────────────────────────────────────── *)

(** Find substring [needle] in [haystack], returning start index or -1. *)
let find_substring (haystack : string) (needle : string) : int =
  let hlen = String.length haystack in
  let nlen = String.length needle in
  if nlen > hlen then -1
  else begin
    let result = ref (-1) in
    (try
      for i = 0 to hlen - nlen do
        if String.sub haystack i nlen = needle then begin
          result := i; raise Exit
        end
      done
    with Exit -> ());
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
  loc : int;  (** end_line - start_line *)
}

(* ── Scope building ────────────────────────────────────────────────── *)

(** Build function scopes from a flat node list, grouped by file.

    Uses a line-range heuristic: a Def's body extends from its line
    to the next Def's line (or end of file) in the same file.
*)
let build_scopes (nodes : Security_node.t list) : scope list =
  (* Group by file *)
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  (* For each file, find Def nodes and their bodies *)
  let scopes = ref [] in
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
    let defs = List.filter (fun n -> n.Security_node.node_type = Security_node.Def) sorted in
    List.iteri (fun i (def : Security_node.t) ->
      let start_line = def.Security_node.line in
      let end_line =
        if i + 1 < List.length defs then
          (List.nth defs (i + 1)).Security_node.line
        else max_int
      in
      let body = List.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type <> Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in
      scopes := { def; body } :: !scopes
    ) defs
  ) by_file;
  List.rev !scopes

(* ── Class scope building ──────────────────────────────────────────── *)

(** Build class scopes from a flat node list.

    Groups Def nodes by their enclosing class/module/enum.
    Returns class_scope list with methods and LOC.
*)
let build_class_scopes (nodes : Security_node.t list) : class_scope list =
  (* Group nodes by file *)
  let by_file = Hashtbl.create 16 in
  List.iter (fun (n : Security_node.t) ->
    let existing = try Hashtbl.find by_file n.Security_node.file with Not_found -> [] in
    Hashtbl.replace by_file n.Security_node.file (n :: existing)
  ) nodes;
  let class_scopes = ref [] in
  Hashtbl.iter (fun _file file_nodes ->
    let sorted = List.sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
    (* Find class/module/enum boundaries *)
    let type_defs = List.filter (fun n ->
      List.mem n.Security_node.node_type
        [Security_node.Class; Security_node.Module; Security_node.Enum]
    ) sorted in
    List.iteri (fun i (td : Security_node.t) ->
      let start_line = td.Security_node.line in
      let end_line =
        if i + 1 < List.length type_defs then
          (List.nth type_defs (i + 1)).Security_node.line
        else 1000000
      in
      (* Get all Def nodes within this class *)
      let methods_in_class = List.filter (fun (n : Security_node.t) ->
        n.Security_node.node_type = Security_node.Def
        && n.Security_node.line >= start_line
        && n.Security_node.line < end_line
      ) sorted in
      (* Build scope for each method *)
      let method_scopes = List.map (fun (def : Security_node.t) ->
        let body = List.filter (fun (n : Security_node.t) ->
          n.Security_node.node_type <> Security_node.Def
          && n.Security_node.line >= def.Security_node.line
          && n.Security_node.line < end_line
          && n.Security_node.line >= start_line
        ) sorted in
        { def; body }
      ) methods_in_class in
      let loc = end_line - start_line in
      class_scopes := { class_node = td; methods = method_scopes; loc } :: !class_scopes
    ) type_defs
  ) by_file;
  List.rev !class_scopes

(* ── Helpers ───────────────────────────────────────────────────────── *)

(** Get the class/module/enum containing a node, by file and line range. *)
let find_enclosing_class (nodes : Security_node.t list) (file : string) (line : int)
    : Security_node.t option =
  let file_nodes = List.filter (fun n -> n.Security_node.file = file) nodes in
  let sorted = List.sort (fun a b -> compare a.Security_node.line b.Security_node.line) file_nodes in
  let type_defs = List.filter (fun n ->
    List.mem n.Security_node.node_type
      [Security_node.Class; Security_node.Module; Security_node.Enum]
  ) sorted in
  (* Find the last type def that starts before or at [line] *)
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