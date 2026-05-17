(* lib/catseye_claws/types.ml *)

(** Claws — code health module types and configuration.

    Claws detects code smells (complexity, structural issues) and DRY
    violations using the same Security_node.t stream as the security engine.

    Findings use standard severity levels:
    - Error (critical) — complexity >= 20, god objects
    - Warning — complexity 10–19, long params, deep nesting
    - Info (clean)    — below all thresholds
*)

type claws_config = {
  (* Per-detector toggles *)
  complexity_enabled : bool;    (** default: true *)
  anatomy_enabled : bool;       (** default: true *)
  dry_enabled : bool;           (** default: true *)
  ameba_enabled : bool;         (** default: false *)
  extra_smells_enabled : bool;  (** default: true *)
  anti_singleton_enabled : bool; (** default: true *)
  lazy_class_enabled : bool;     (** default: true *)
  large_class_enabled : bool;     (** default: true *)

  (* Complexity thresholds *)
  complexity_warning : int;     (** default: 10 *)
  complexity_critical : int;    (** default: 20 *)

  (* Anatomy thresholds *)
  max_params : int;             (** default: 5 *)
  max_params_critical : int;    (** default: 8 *)
  max_nesting : int;            (** default: 5 *)
  max_nesting_critical : int;   (** default: 7 *)
  max_methods_per_file : int;   (** default: 20 *)

  (* DRY *)
  dry_window_size : int;        (** default: 8 *)
  dry_min_occurrences : int;    (** default: 4 *)

  (* Ameba *)
  ameba_path : string;          (** default: "ameba" *)

  (* Extra smells *)
  long_method_warning : int;    (** default: 30 nodes *)
  long_method_critical : int;   (** default: 50 nodes *)
  complex_conditional_threshold : int;  (** default: 3 operators *)
  message_chain_threshold : int; (** default: 5 segments *)
  data_clumps_enabled : bool;   (** default: true *)
  data_clumps_threshold : int;  (** default: 3 functions *)
  complex_match_warning : int;  (** default: 5 when branches *)
  complex_match_critical : int; (** default: 10 when branches *)
  concurrency_enabled : bool;  (** default: true *)

  (* Class smells *)
  lazy_class_method_threshold : int;  (** default: 3 *)
  large_class_loc_warning : int;     (** default: 200 lines *)
  large_class_loc_critical : int;    (** default: 500 lines *)

  (* Per-rule suppression: rule name -> glob patterns for files to suppress *)
  suppress : (string, string list) Hashtbl.t;  (** default: empty *)
}

let default_config = {
  complexity_enabled = true;
  anatomy_enabled = true;
  dry_enabled = true;
  ameba_enabled = false;
  extra_smells_enabled = true;
  anti_singleton_enabled = true;
  complexity_warning = 10;
  complexity_critical = 20;
  max_params = 5;
  max_params_critical = 8;
  max_nesting = 5;
  max_nesting_critical = 7;
  max_methods_per_file = 20;
  dry_window_size = 8;
  dry_min_occurrences = 4;
  ameba_path = "ameba";
  long_method_warning = 30;
  long_method_critical = 50;
  complex_conditional_threshold = 3;
  message_chain_threshold = 5;
  data_clumps_enabled = true;
  data_clumps_threshold = 3;
  complex_match_warning = 5;
  complex_match_critical = 10;
  concurrency_enabled = true;
  lazy_class_enabled = true;
  large_class_enabled = true;
  lazy_class_method_threshold = 3;
  large_class_loc_warning = 200;
  large_class_loc_critical = 500;
  suppress = Hashtbl.create 0;
}
