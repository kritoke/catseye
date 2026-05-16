(* lib/catseye_il/cfg_dominator.ml
   Dominator analysis on the CFG using ocamlgraph's Dominator module.

   Computes the dominator tree for a CFG and provides:
   - Block dominance queries (does block A dominate block B?)
   - Guard block detection (blocks containing sanitizer calls)
   - Finding suppression when a sanitizer guard dominates a sink
*)

open Il_types

(* ── Dominator computation ──────────────────────────────────────────── *)

(** Dominator module specialized to our int-vertex graph *)
module Dom = Graph.Dominator.Make (Cfg_graph.G)

(** Result of dominator analysis *)
type t = {
  cfg : Cfg_graph.t;
  idom : int -> int;               (* immediate dominator function *)
  dom : int -> int -> bool;        (* full dominance check *)
  dom_tree : int -> int list;      (* children in dominator tree *)
  guard_blocks : int list;         (* blocks containing sanitizer calls *)
}

(** Known sanitizer function name patterns.
    These are functions that validate/cleanse tainted data.
    If a call to one of these dominates a sink, the finding is likely a FP. *)
let known_sanitizers =
  [ "check_ssrf"; "validate_url"; "validate_path"; "validate_input"
  ; "sanitize"; "escape"; "encode"; "clean"; "filter"
  ; "url_validator"; "path_validator"
  ; "verify"; "authenticate"; "authorize"
  ; "File.expand_path"; "URI.parse"
  ]

(** Check if a function name matches a known sanitizer pattern. *)
let is_sanitizer_call (fn_name : string) : bool =
  let lower = String.lowercase_ascii fn_name in
  List.exists (fun pat ->
    let lpat = String.lowercase_ascii pat in
    String.length lower >= String.length lpat &&
    let prefix = String.sub lower 0 (String.length lpat) in
    prefix = lpat
  ) known_sanitizers

(** Check if any node in a block is a sanitizer call. *)
let block_has_sanitizer (cfg : Cfg_graph.t) (block_id : int) : bool =
  let nodes = Cfg_graph.block_nodes cfg block_id in
  List.exists (fun node ->
    match node with
    | ILCall (_, fn_name, _, _) -> is_sanitizer_call fn_name
    | ILAssign (_, IECall (fn_name, _, _), _) -> is_sanitizer_call fn_name
    | _ -> false
  ) nodes

(** Check if any node in a block calls a function from a given sanitizer list.
    This version uses the rule-specific sanitizers from the KDL rules. *)
let block_has_rule_sanitizer (cfg : Cfg_graph.t) (block_id : int)
    (sanitizers : string list) : bool =
  let nodes = Cfg_graph.block_nodes cfg block_id in
  List.exists (fun node ->
    match node with
    | ILCall (_, fn_name, _, _) ->
      List.exists (fun _pat ->
        Catseye_rules.Interpreter.matches_sanitizer sanitizers fn_name
      ) sanitizers
      (* Also check known built-in sanitizers *)
      || is_sanitizer_call fn_name
    | ILAssign (_, IECall (fn_name, _, _), _) ->
      is_sanitizer_call fn_name
    | _ -> false
  ) nodes

(** Compute dominator analysis for a CFG.
    Returns dominance functions + identified guard blocks. *)
let compute (cfg : Cfg_graph.t) : t =
  let entry = cfg.Cfg_graph.entry in
  let idom = Dom.compute_idom cfg.Cfg_graph.graph entry in
  let dom = Dom.idom_to_dom idom in
  let dom_tree = Dom.idom_to_dom_tree cfg.Cfg_graph.graph idom in
  (* Identify blocks that contain sanitizer calls *)
  let guard_blocks =
    let all_guards = ref [] in
    Cfg_graph.iter_vertices cfg (fun vid ->
      if block_has_sanitizer cfg vid then
        all_guards := vid :: !all_guards
    );
    !all_guards
  in
  { cfg; idom; dom; dom_tree; guard_blocks }

(** Check if any guard block dominates the given block.
    Returns true if there exists a sanitizer guard that must execute
    before reaching this block on every path from entry. *)
let is_guarded (dom_data : t) (block_id : int) : bool =
  List.exists (fun guard ->
    dom_data.dom guard block_id
  ) dom_data.guard_blocks

(** Check if a specific sanitizer dominates the given block.
    Useful for rule-specific suppression: only suppress SSRF if
    check_ssrf dominates, etc. *)
let is_sanitized_by (dom_data : t) (block_id : int)
    (sanitizer_names : string list) : bool =
  let nodes_of vid = Cfg_graph.block_nodes dom_data.cfg vid in
  (* Walk dominator chain from block_id upward to entry *)
  let rec walk_up current =
    if current = dom_data.cfg.Cfg_graph.entry then false
    else begin
      let parent = dom_data.idom current in
      (* Check if parent block contains a relevant sanitizer *)
      let parent_nodes = nodes_of parent in
      let has_matching_sanitizer = List.exists (fun node ->
        match node with
        | ILCall (_, fn_name, _, _) ->
          is_sanitizer_call fn_name ||
          List.exists (fun _s ->
            Catseye_rules.Interpreter.matches_sanitizer sanitizer_names fn_name
          ) sanitizer_names
        | ILAssign (_, IECall (fn_name, _, _), _) ->
          is_sanitizer_call fn_name
        | _ -> false
      ) parent_nodes in
      if has_matching_sanitizer then true
      else walk_up parent
    end
  in
  walk_up block_id
