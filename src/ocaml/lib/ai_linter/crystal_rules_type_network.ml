(* src/ocaml/lib/ai_linter/crystal_rules_type_network.ml
   Category 18: Type & Network

   Detects type-checker abuse (manual is_a?/as/responds_to? instead of
   polymorphism) and hardcoded network port numbers.
 *)

open Base

open Catseye_ast.Types

include Crystal_rules_helpers

(** Rule: Type Checker Abuse

    Detects 3+ is_a?/as/responds_to? calls in one function. *)
let detect_type_checker_abuse (m : t) =
  let is_type_check (name : string) =
    let suffixes = ["is_a?"; "responds_to?"; "kind_of?"; "nil?"; "is_a"] in
    name_ends_with_any name suffixes
  in
  map_functions m (fun fname body line ->
    let checks = List.filter (fun (n, _) -> is_type_check n) (collect_app_names body) in
    if List.length checks > 2 then
      [Printf.sprintf "Function '%s' has %d type-check calls (max 2) — use polymorphism or overloads"
         fname (List.length checks), line]
    else []
  )

(** Rule: Hardcoded Port

    Detects hardcoded port numbers (80, 443, 3000, etc.) in network calls. *)
let detect_hardcoded_port (m : t) =
  let common_ports = [80; 443; 3000; 4000; 5000; 8000; 8080; 8443; 9090] in
  let network_prefixes = ["HTTP::"; "http"; "TCPServer"; "TCPSocket"; "URI"; "socket"] in
  let find_port_literals (e : expr) : (int * int) list =
    map_subexpressions (fun e ->
      match e.expr_value with
      | ELiteral (LInt i) ->
        (match Stdlib.int_of_string_opt i with
         | Some v when List.mem v common_ports -> [(v, e.expr_location.start.line)]
         | _ -> [])
      | _ -> []
    ) e
  in
  map_functions m (fun _name body _line ->
    let calls = collect_app_names body in
    let has_network = List.exists (fun (n, _) -> name_starts_with_any n network_prefixes) calls in
    if has_network then
      List.map (fun (port, line) ->
        Printf.sprintf "Hardcoded port %d in network context — use environment variable or config" port, line
      ) (find_port_literals body)
    else []
  )
