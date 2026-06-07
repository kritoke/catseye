(* src/ocaml/lib/ai_linter/crystal_rules_type_network.ml
   Category 18: Type & Network

   Detects type-checker abuse (manual is_a?/as/responds_to? instead of
   polymorphism) and hardcoded network port numbers.

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

let detect_type_checker_abuse (m : t) =
  let max_checks = 2 in
  
  let is_type_check (name : string) =
    String.length name >= 5 &&
    let suffixes = ["is_a?"; "responds_to?"; "kind_of?"; "nil?"; "is_a"] in
    List.exists (fun s ->
      String.length name >= String.length s &&
      String.sub name (String.length name - String.length s) (String.length s) = s
    ) suffixes
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let checks = List.filter (fun (n, _) -> is_type_check n) (collect_app_names body) in
      if List.length checks > max_checks then
        collected := (Printf.sprintf
          "Function '%s' has %d type-check calls (max %d) — use polymorphism or overloads"
          name (List.length checks) max_checks, item.item_location.start.line) :: !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Hardcoded Port
    Detects hardcoded port numbers (80, 443, 3000, 8080, etc.) in
    network-related calls. AI often bakes in port numbers instead of
    reading from configuration. *)

let detect_hardcoded_port (m : t) =
  let common_ports = [80; 443; 3000; 4000; 5000; 8000; 8080; 8443; 9090] in
  let network_prefixes = ["HTTP::"; "http"; "TCPServer"; "TCPSocket"; "URI"; "socket"] in
  let is_network_context (calls : (string * int) list) =
    List.exists (fun (n, _) ->
      List.exists (fun prefix ->
        String.length n >= String.length prefix &&
        String.sub n 0 (String.length prefix) = prefix
      ) network_prefixes
    ) calls
  in
  let rec find_port_literals (e : expr) : (int * int) list =
    match e.expr_value with
    | ELiteral (LInt i) ->
      let port_val = Stdlib.int_of_string_opt i in
      (match port_val with
       | Some v when List.mem v common_ports -> [(v, e.expr_location.start.line)]
       | _ -> [])
    | EBlock es -> List.concat_map find_port_literals es
    | ELet (_, e1, e2) -> find_port_literals e1 @ find_port_literals e2
    | EApp (fn, args) -> find_port_literals fn @ List.concat_map find_port_literals args
    | _ -> []
  in
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let calls = collect_app_names body in
      if is_network_context calls then
        List.concat_map (fun (port, line) ->
          [Printf.sprintf "Hardcoded port %d in network context — use environment variable or config" port, line]
        ) (find_port_literals body)
      else []
    | _ -> []
  ) m.mod_items

(* ── Category 19: Style ─────────────────────────────────────────────── *)

(** Rule: Unless with Else
    Detects unless ... else constructs. These are confusing double-negatives.
    AI often generates 'unless condition else ...' which should be
    rewritten as 'if condition ... else ...'. *)