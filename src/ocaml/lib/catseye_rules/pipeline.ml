(* lib/catseye_rules/pipeline.ml
   Pattern analysis pipeline for complex semantic security rules.

   This module provides pattern matching and analysis patterns for
   writing security rule checkers. *)

open Base

(* ── Error Types ─────────────────────────────────────────────────────── *)

(** Represents a security analysis error at a specific location *)
type 'a analysis_error = {
  file : string;
  line : int;
  rule : string;
  details : string;
  context : 'a;
}

(* ── Exploit Pattern Analysis ─────────────────────────────────────── *)

module Hiss = struct
  (** Represents a potential exploit pattern *)
  type exploit = {
    name : string;
    severity : string;
    location : string;
    pattern : string;
    confidence : float;
  }

  (** Result of exploit analysis *)
  type analysis_result = {
    exploits_found : exploit list;
    clean : bool;
  }

  (** Check for "Tradition Breaker" pattern: name overrides parent in hierarchy *)
  let check_tradition_breaker 
      (class_name : string)
      (hierarchy : (string * string) list)
      (method_names : string list) : exploit option =
    match List.Assoc.find hierarchy ~equal:String.equal class_name with
    | Some _ when List.length method_names > 0 ->
        Some {
          name = "Tradition Breaker";
          severity = "medium";
          location = class_name;
          pattern = "Methods override in class hierarchy";
          confidence = 0.7;
        }
    | _ -> None

  (** Check for suspicious naming patterns *)
  let check_suspicious_names
      (class_name : string)
      (params : string list) : exploit option =
    let suspicious = 
      List.filter params ~f:(fun p ->
        String.is_suffix ~suffix:"input" p ||
        String.is_suffix ~suffix:"data" p ||
        String.is_suffix ~suffix:"user" p
      )
    in
    if List.length suspicious > 0 then
      Some {
        name = "Suspicious Parameter";
        severity = "high";
        location = class_name;
        pattern = "Parameter without validation prefix";
        confidence = 0.8;
      }
    else
      None

  (** Analyze a class for all exploit patterns *)
  let analyze_class
      (class_name : string)
      (hierarchy : (string * string) list)
      (method_names : string list)
      (params : string list) : analysis_result =
    let exp = 
      match check_tradition_breaker class_name hierarchy method_names with
      | Some e -> Some e
      | None -> check_suspicious_names class_name params
    in
    match exp with
    | Some e -> { exploits_found = [e]; clean = false }
    | None -> { exploits_found = []; clean = true }
end

(* ── Simple Pipeline Builder ──────────────────────────────────────────── *)

(** A pipeline stage that can transform data *)
type ('a, 'b) stage = {
  name : string;
  run : 'a -> 'b;
}

(** Create a named pipeline stage *)
let stage ~(name : string) (f : 'a -> 'b) : ('a, 'b) stage =
  { name; run = f }

(** Run a single stage *)
let run_stage (s : ('a, 'b) stage) (input : 'a) : 'b =
  s.run input

(* ── Validation ─────────────────────────────────────────────────────── *)

(** Validate naming conventions *)
let validate_name (name : string) : bool =
  not (String.is_prefix ~prefix:"__" name || String.is_suffix ~suffix:"__" name)

(** Check if a class name exists in a hierarchy *)
let find_parent_class (class_name : string) (hierarchy : (string * string) list) 
    : string option =
  List.Assoc.find hierarchy ~equal:String.equal class_name

(* ── Complex Pattern Analysis ─────────────────────────────────────── *)

(** Detect complex inheritance anomalies *)
let detect_inheritance_anomalies 
    (hierarchy : (string * string) list)
    (class_names : string list) : Hiss.exploit list =
  List.filter_map class_names ~f:(fun class_name ->
    match find_parent_class class_name hierarchy with
    | Some _ -> Hiss.check_tradition_breaker class_name hierarchy []
    | None -> None
  )

(* ── Module Graph Analysis ──────────────────────────────────────────── *)

(* ── Semantic Validation ───────────────────────────────────────────── *)

module SemanticValidator = struct
  type validation_error = {
    rule : string;
    node : string;
    message : string;
  }

  (** Validate class hierarchy consistency *)
  let validate_hierarchy (class_name : string) (parent_opt : string option) : bool =
    match parent_opt with
    | None -> true
    | Some parent_name ->
        String.length parent_name = 0 || not (String.is_prefix ~prefix:"_" class_name)

  (** Validate method visibility *)
  let validate_visibility (visibility : string) : bool =
    match visibility with
    | "private" | "protected" | "public" -> true
    | _ -> false
end

(* ── Export types for rule checking ─────────────────────────────── *)

module Rules = struct
  type rule_result = {
    passed : bool;
    details : string;
    severity : string;
  }

  let check_naming_convention (name : string) : rule_result =
    if String.is_prefix ~prefix:"_" name then
      { passed = false; details = "Leading underscore"; severity = "warning" }
    else
      { passed = true; details = "Named correctly"; severity = "info" }

  let check_visibility (visibility : string) : rule_result =
    match visibility with
    | "private" | "protected" | "public" ->
        { passed = true; details = "Valid visibility"; severity = "info" }
    | _ ->
        { passed = false; details = "Invalid visibility"; severity = "error" }
end
