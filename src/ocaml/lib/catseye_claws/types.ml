(* lib/catseye_claws/types.ml *)

(** Claws — code health module types and configuration.

    Claws detects code smells (complexity, structural issues) and DRY
    violations using the same Security_node.t stream as the security engine.

    Findings use the Hunter taxonomy:
    - HISS (critical) — complexity >= 20, god objects
    - MEOW (warning)  — complexity 10–19, long params, deep nesting
    - PURR (clean)    — below all thresholds
*)

type claws_config = {
  (* Per-detector toggles *)
  complexity_enabled : bool;    (** default: true *)
  anatomy_enabled : bool;       (** default: true *)
  dry_enabled : bool;           (** default: true *)
  ameba_enabled : bool;         (** default: false *)

  (* Complexity thresholds *)
  complexity_warning : int;     (** default: 10 *)
  complexity_critical : int;    (** default: 20 *)

  (* Anatomy thresholds *)
  max_params : int;             (** default: 5 *)
  max_params_critical : int;    (** default: 8 *)
  max_nesting : int;            (** default: 4 *)
  max_nesting_critical : int;   (** default: 6 *)
  max_methods_per_file : int;   (** default: 20 *)

  (* DRY *)
  dry_window_size : int;        (** default: 6 *)
  dry_min_occurrences : int;    (** default: 2 *)

  (* Ameba *)
  ameba_path : string;          (** default: "ameba" *)
}

let default_config = {
  complexity_enabled = true;
  anatomy_enabled = true;
  dry_enabled = true;
  ameba_enabled = false;
  complexity_warning = 10;
  complexity_critical = 20;
  max_params = 5;
  max_params_critical = 8;
  max_nesting = 4;
  max_nesting_critical = 6;
  max_methods_per_file = 20;
  dry_window_size = 6;
  dry_min_occurrences = 2;
  ameba_path = "ameba";
}
