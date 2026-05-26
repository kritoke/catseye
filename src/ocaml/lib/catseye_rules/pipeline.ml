(* lib/catseye_rules/pipeline.ml
   Monadic Result pipeline for complex semantic security rules.

   This module provides railway-oriented programming patterns for
   writing clean, composable security rule checkers using Base monads. *)

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

(** Result type for security rule checks *)
module Result = struct
  type ('a, 'e) t = ('a, 'e) result
  
  let return x = Ok x
  
  let ( >>= ) (r : ('a, 'e) t) (f : 'a -> ('b, 'e) t) : ('b, 'e) t =
    match r with
    | Ok v -> f v
    | Error e -> Error e
  
  let ( >>| ) (r : ('a, 'e) t) (f : 'a -> 'b) : ('b, 'e) t =
    match r with
    | Ok v -> Ok (f v)
    | Error e -> Error e
  
  let ( >>|? ) (r : ('a, 'e) t) (f : 'a -> 'e) : ('b, 'e) t =
    match r with
    | Ok v -> Error (f v)
    | Error e -> Error e
end

(* ── Pipeline Builder ────────────────────────────────────────────────── *)

(** A pipeline stage that can transform data or halt on error *)
type ('a, 'b, 'e) stage = {
  name : string;
  run : 'a -> ('b, 'e) Result.t;
}

(** Create a named pipeline stage *)
let stage ~(name : string) (f : 'a -> ('b, 'e) Result.t) : ('a, 'b, 'e) stage =
  { name; run = f }

(** Run a single stage *)
let run_stage (s : ('a, 'b, 'e) stage) (input : 'a) : ('b, 'e) Result.t =
  s.run input

(* ── Semantic Query Helpers ─────────────────────────────────────────── *)

(** Check if a class inherits from a specific parent *)
let find_parent_class (class_name : string) (hierarchy : (string * string) list) 
    : string option Result.t =
  match List.Assoc.find hierarchy ~equal:String.equal class_name with
  | Some parent -> Ok (Some parent)
  | None -> Ok None

(** Find all methods inherited from a parent class *)
let find_inherited_methods (parent : string) (methods : (string * string list) list)
    : string list Result.t =
  match List.Assoc.find methods ~equal:String.equal parent with
  | Some m -> Ok m
  | None -> Ok []

(** Verify that method bodies are empty (stub methods) *)
let verify_bodies_empty (methods : string list) (bodies : string list)
    : (unit, string) Result.t =
  let check_body body =
    match String.strip body with
    | "" -> Ok ()
    | _ -> Error "Non-empty body found"
  in
  match List.zip methods bodies with
  | Ok pairs ->
    List.fold_result pairs ~init:() ~f:(fun () (_, body) -> check_body body)
  | Error _ -> Error "Method/body count mismatch"

(* ── "Hiss" Exploit Simulation ─────────────────────────────────────── *)

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

  (** Check for "Tradition Breaker" pattern: method redefines parent but is empty *)
  let check_tradition_breaker 
      (class_node : Catseye_ast.Types.class_def)
      (hierarchy : (string * string) list)
      (method_bodies : (string, string) Hashtbl.t) : exploit option Result.t =
    match find_parent_class class_node.name hierarchy with
    | Error e -> Error e
    | Ok None -> Ok None  (* No parent, can't be tradition breaker *)
    | Ok (Some parent_name) ->
      (* Check if this class overrides parent methods *)
      let overridden = 
        List.filter class_node.methods ~f:(fun m ->
          Option.is_some (Hashtbl.find method_bodies m.name)
        )
      in
      match overridden with
      | [] -> Ok None
      | methods ->
        (* Check for empty bodies in overridden methods *)
        let empty_overrides = 
          List.filter methods ~f:(fun m ->
            match Hashtbl.find method_bodies m.name with
            | Some body -> String.is_empty (String.strip body)
            | None -> false
          )
        in
        match empty_overrides with
        | [] -> Ok None
        | bad_methods ->
          Ok (Some {
            name = "Tradition Breaker";
            severity = "medium";
            location = class_node.name;
            pattern = "Empty method overrides: " ^ (String.concat ~sep:", " (List.map bad_methods ~f:(fun m -> m.name)));
            confidence = 0.85;
          })

  (** Check for "Blob" pattern: large class with many dependencies *)
  let check_blob 
      (class_node : Catseye_ast.Types.class_def)
      (dependencies : string list)
      (loc_threshold : int) : exploit option Result.t =
    let method_count = List.length class_node.methods in
    let dep_count = List.length dependencies in
    let has_many_deps = dep_count > 10 in
    let has_many_methods = method_count > 20 in
    if has_many_deps && has_many_methods then
      Ok (Some {
        name = "Blob";
        severity = "high";
        location = class_node.name;
        pattern = Printf.sprintf "Class has %d methods and %d dependencies (thresholds: 20 methods, 10 deps)" 
          method_count dep_count;
        confidence = 0.9;
      })
    else
      Ok None

  (** Check for "Refused Parent Bequest" pattern *)
  let check_refused_bequest
      (class_node : Catseye_ast.Types.class_def)
      (hierarchy : (string * string) list)
      (parent_methods : string list)
      (used_methods : string list) : exploit option Result.t =
    find_parent_class class_node.name hierarchy
    >>= (fun parent_opt ->
      match parent_opt with
      | None -> Ok None
      | Some parent ->
        let unused_parent_methods = 
          List.filter parent_methods ~f:(fun m -> not (List.mem used_methods m ~equal:String.equal))
        in
        if List.is_empty unused_parent_methods then
          Ok None
        else
          Ok (Some {
            name = "Refused Parent Bequest";
            severity = "medium";
            location = class_node.name;
            pattern = Printf.sprintf "Ignores parent methods: %s" 
              (String.concat ~sep:", " unused_parent_methods);
            confidence = 0.75;
          })
    )

  (** Analyze a class for all known exploit patterns *)
  let analyze_class
      (class_node : Catseye_ast.Types.class_def)
      (hierarchy : (string * string) list)
      (method_bodies : (string, string) Hashtbl.t)
      (dependencies : string list)
      (used_methods : string list) : analysis_result =
    let rec collect_exploits acc = function
      | [] -> List.rev acc
      | check_fn :: rest ->
        match check_fn class_node hierarchy method_bodies dependencies used_methods with
        | Ok (Some exploit) -> collect_exploits (exploit :: acc) rest
        | Ok None -> collect_exploits acc rest
        | Error _ -> collect_exploits acc rest
    in
    let checks = [
      (fun c h m d u -> check_tradition_breaker c h m);
      (fun c h m d u -> check_blob c d 200);
      (fun c h m d u -> check_refused_bequest c h [] u);
    ] in
    let exploits = collect_exploits [] checks in
    { exploits_found = exploits; clean = List.is_empty exploits }
end

(* ── Railway-Oriented Rule Building ─────────────────────────────────── *)

module RuleBuilder = struct
  type 'a context = {
    file : string;
    line : int;
    node : 'a;
    findings : Finding.t list;
  }

  and finding = {
    rule : string;
    severity : string;
    message : string;
  }

  (** A rule that can emit findings *)
  type 'a rule = {
    name : string;
    check : 'a context -> finding list;
  }

  (** Compose two rules sequentially *)
  let ( >>> ) (r1 : 'a rule) (r2 : 'a rule) : 'a rule =
    {
      name = r1.name ^ " + " ^ r2.name;
      check = (fun ctx -> 
        let findings1 = r1.check ctx in
        let ctx' = { ctx with findings = ctx.findings @ findings1 } in
        let findings2 = r2.check ctx' in
        findings1 @ findings2
      );
    }

  (** Combine two rules to run in parallel (both checks) *)
  let ( ||| ) (r1 : 'a rule) (r2 : 'a rule) : 'a rule =
    {
      name = r1.name ^ " || " ^ r2.name;
      check = (fun ctx ->
        let findings1 = r1.check ctx in
        let findings2 = r2.check ctx in
        findings1 @ findings2
      );
    }

  (** Create a simple rule from a predicate and error message *)
  let rule ~(name : string) ~(check : 'a -> bool) ~(message : string) : 'a rule =
    {
      name;
      check = (fun ctx ->
        if check ctx.node then
          [{ rule = name; severity = "medium"; message }]
        else
          []
      );
    }

  (** Run a rule against a node *)
  let run (r : 'a rule) (node : 'a) ~(file : string) ~(line : int) : finding list =
    r.check { file; line; node; findings = [] }
end

(* ── Version ─────────────────────────────────────────────────────────── *)

let version = "0.1.0"