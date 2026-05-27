(* lib/catseye_claws/smells.ml *)

open Base

(* Note: Base has compatible String and List modules.
   Only equality operators need explicit stdlib access since Base's (=) is polymorphic. *)
let ( = ) = Stdlib.( = )
let ( <>) = Stdlib.( <> )

module Architectural = Architectural_smells

(** Unified Claws pipeline.

    Orchestrates all code smell detectors and returns merged findings.
    Each detector can be individually toggled via claws_config.

    Detectors:
    - Complexity: cyclomatic complexity per function
    - Anatomy: long params, deep nesting, god objects
    - DRY: structural duplication detection
    - Extra: long method, complex conditional, message chains, data clumps
    - Ameba: Crystal linter integration (optional)
*)

open Catseye_types

(** Simple glob matcher supporting * and ** patterns.
    * matches any chars except /
    ** matches any chars including / *)
let glob_match (pattern : string) (path : string) : bool =
  let plen = String.length pattern in
  let pathlen = String.length path in
  (* If no special chars, do plain comparison *)
  if not (String.mem pattern '*') then
    pattern = path
  else if pattern = "**" then true
  else begin
    let rec match_at pi fi =
      if pi = plen then fi = pathlen
      else if fi = pathlen then
        pi < plen && pattern.[pi] = '*' && match_at (pi + 1) fi
      else begin
        let pc = pattern.[pi] in
        if pc = '?' || pc = path.[fi] then match_at (pi + 1) (fi + 1)
        else if pc = '*' then
          (* Try matching zero or more chars *)
          if pi + 2 <= plen && pattern.[pi + 1] = '*' then
            (* ** — match any including / *)
            let skip = if pi + 2 < plen && pattern.[pi + 2] = '/' then 3 else 2 in
            match_at (pi + skip) fi || match_at pi (fi + 1)
          else
            (* * — match any except / *)
            if path.[fi] = '/' then match_at (pi + 1) fi
            else match_at (pi + 1) fi || match_at pi (fi + 1)
        else false
      end
    in
    match_at 0 0
  end

(** Check if a finding should be suppressed based on config.
    Returns true if the finding matches a suppression rule. *)
let is_suppressed (config : Types.claws_config) (f : Finding.t) : bool =
  match Map.find config.Types.suppress f.Finding.rule with
  | None -> false
  | Some patterns ->
    List.exists patterns ~f:(fun pat -> glob_match pat f.Finding.file)

(** Deduplicate findings by (rule, file, line) key. *)
let deduplicate (findings : Finding.t list) : Finding.t list =
  let seen = Map.empty (module String) in
  let seen = ref seen in
  let rec dedup_findings = function
    | [] -> []
    | (f : Finding.t) :: rest ->
      let key = Printf.sprintf "%s|%s|%d" f.Finding.rule f.Finding.file f.Finding.line in
      if Map.mem !seen key then dedup_findings rest
      else begin seen := Map.set !seen ~key ~data:(); (f :: dedup_findings rest) end
  in
  dedup_findings findings

(** Run all Claws detectors and return merged findings. *)
let analyze (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  let complexity_findings =
    if config.complexity_enabled then Complexity.analyze nodes config
    else []
  in
  let anatomy_findings =
    if config.anatomy_enabled then Anatomy.analyze nodes config
    else []
  in
  let dry_findings =
    if config.dry_enabled then Dry.detect nodes config
    else []
  in
  let extra_findings =
    if config.extra_smells_enabled then Extra_smells.analyze nodes config
    else []
  in
  let anti_singleton_findings =
    if config.anti_singleton_enabled then Anti_singleton.analyze nodes config
    else []
  in
  let lazy_class_findings =
    if config.lazy_class_enabled then Lazy_class.analyze nodes config
    else []
  in
  let large_class_findings =
    if config.large_class_enabled then Large_class.analyze nodes config
    else []
  in
  let blob_findings =
    if config.large_class_enabled then Blob.analyze nodes config
    else []
  in
  let spaghetti_code_findings =
    Spaghetti_code.analyze nodes config
  in
  let hierarchy_findings =
    Hierarchy_smells.analyze nodes config
  in
  let hub_like_findings =
    if config.large_class_enabled then Hub_like_module.analyze nodes config
    else []
  in
  let shotgun_findings =
    if config.large_class_enabled then Shotgun_surgery.analyze nodes config
    else []
  in
  let concurrency_findings =
    if config.concurrency_enabled then Concurrency.analyze nodes config
    else []
  in
  let ameba_findings = Ameba_hook.run config nodes in
  (complexity_findings @ anatomy_findings @ dry_findings @ extra_findings @ anti_singleton_findings @ lazy_class_findings @ large_class_findings @ blob_findings @ spaghetti_code_findings @ hierarchy_findings @ hub_like_findings @ shotgun_findings @ concurrency_findings @ ameba_findings)
  |> deduplicate
  |> List.filter ~f:(fun f -> not (is_suppressed config f))

(** Run all Claws detectors on AST-native input and return merged findings.
    Uses CatseyeAST.t directly for modules that have been migrated.
    Falls back to Security_node.t for unmigrated modules. *)
let analyze_ast (modules : Catseye_ast.Types.t list) (config : Types.claws_config)
    : Finding.t list =
  let complexity_findings =
    if config.complexity_enabled then Complexity_ast.analyze modules config
    else []
  in
  let anatomy_findings =
    if config.anatomy_enabled then Anatomy_ast.analyze modules config
    else []
  in
  let dry_findings =
    if config.dry_enabled then Dry_ast.analyze modules config
    else []
  in
  let extra_findings =
    if config.extra_smells_enabled then Extra_smells_ast.analyze modules config
    else []
  in
  let concurrency_findings =
    if config.concurrency_enabled then Concurrency_ast.analyze modules config
    else []
  in
  let architectural_findings = Architectural.check_god_class modules @ Architectural.check_inappropriate_intimacy modules in
  (complexity_findings @ anatomy_findings @ dry_findings @ extra_findings @ concurrency_findings @ architectural_findings)
  |> deduplicate
  |> List.filter ~f:(fun f -> not (is_suppressed config f))