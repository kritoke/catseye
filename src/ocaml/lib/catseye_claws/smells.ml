(* lib/catseye_claws/smells.ml *)

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

(** Deduplicate findings by (rule, file, line) key. *)
let deduplicate (findings : Finding.t list) : Finding.t list =
  let seen = Hashtbl.create 64 in
  List.filter (fun (f : Finding.t) ->
    let key = Printf.sprintf "%s|%s|%d" f.Finding.rule f.Finding.file f.Finding.line in
    if Hashtbl.mem seen key then false
    else begin Hashtbl.add seen key true; true end
  ) findings

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
  let concurrency_findings =
    if config.concurrency_enabled then Concurrency.analyze nodes config
    else []
  in
  let ameba_findings = Ameba_hook.run config nodes in
  (complexity_findings @ anatomy_findings @ dry_findings @ extra_findings @ concurrency_findings @ ameba_findings)
  |> deduplicate
