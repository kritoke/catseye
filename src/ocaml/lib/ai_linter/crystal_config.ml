(* src/ocaml/lib/ai_linter/crystal_config.ml
   Crystal rule configuration

   Centralizes the magic numbers and string lists that detectors
   use as thresholds, ports, etc. Two configurations are exported:
   [default] (production-friendly) and [strict] (tighter, for CI gates
   or for "show me everything" debugging).

   Each detector reads the relevant fields directly from the
   configuration record. To add a new tunable, add a field to
   [t] below, give it a value in [default] and [strict], and reference
   it from the detector.
 *)

open Base

(* ── Thresholds ──────────────────────────────────────────────────────── *)

type t = {
  (* Long method (Category 9) *)
  long_method_max_nodes : int;

  (* Too many parameters (Category 15) *)
  too_many_params_max : int;

  (* Primitive obsession (Category 2) *)
  primitive_obsession_min_params : int;

  (* Complex conditional (Category 11) *)
  complex_conditional_max_operators : int;

  (* Message chain / Law of Demeter (Category 11) *)
  message_chain_max_depth : int;

  (* Nested ternary (Category 11) *)
  nested_ternary_max_depth : int;

  (* Callback hell (Category 14) *)
  callback_hell_max_depth : int;

  (* Data clump (Category 12) *)
  data_clump_min_co_occurrence : int;

  (* Feature envy (Category 12) *)
  feature_envy_min_calls : int;
  feature_envy_threshold : float;

  (* Type checker abuse (Category 18) *)
  type_checker_max : int;
}

(* ── Default configuration (production-friendly) ────────────────────── *)

let default = {
  long_method_max_nodes = 80;
  too_many_params_max = 6;
  primitive_obsession_min_params = 3;
  complex_conditional_max_operators = 3;
  message_chain_max_depth = 4;
  nested_ternary_max_depth = 3;
  callback_hell_max_depth = 2;
  data_clump_min_co_occurrence = 3;
  feature_envy_min_calls = 5;
  feature_envy_threshold = 0.7;
  type_checker_max = 2;
}

(* ── Strict configuration (tighter thresholds for CI) ───────────────── *)

let strict = {
  long_method_max_nodes = 50;
  too_many_params_max = 4;
  primitive_obsession_min_params = 2;
  complex_conditional_max_operators = 2;
  message_chain_max_depth = 3;
  nested_ternary_max_depth = 2;
  callback_hell_max_depth = 1;
  data_clump_min_co_occurrence = 2;
  feature_envy_min_calls = 3;
  feature_envy_threshold = 0.5;
  type_checker_max = 1;
}
