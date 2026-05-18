(* src/ocaml/lib/ai_linter/rust_rules.ml
   Rust-specific AST rules for antipattern and AI hallucination detection.
   
   Key areas:
   1. AI hallucinated functions (Python/Ruby/Go APIs used in Rust)
   2. Unsafe patterns: unwrap(), expect(), panic
   3. Common mistakes: cloning, String vs &str
   4. Best practices: proper error handling
*)

open Catseye_ast.Types
open Types

(* ── Hallucinated Functions Detection ─────────────────────────────── *)

let hallucinated_rust = [
  (* Python patterns *)
  ("len", "Rust: use .len() for collections");
  ("range", "Rust: use for i in 0..n or (0..n).into_iter()");
  ("unwrap_result", "Rust: use ? or match instead of unwrap_result");
  ("dict", "Rust: use std::collections::HashMap");
  ("list", "Rust: use Vec<T>");
  ("print", "Rust: use print!() or println!()");
  ("input", "Rust: use std::io::stdin().read_line()");
  ("list.append", "Rust: use Vec::push()");
  ("dict.get", "Rust: use HashMap::get() returns Option<&V>");
  ("json.loads", "Rust: use serde_json::from_str()");
  ("copy", "Rust: use .clone()");
  ("lambda", "Rust: use closures: |x| x + 1");
  ("__init__", "Rust: use fn new() -> Self");
  ("raise", "Rust: use panic!() or return Err()");
  ("try", "Rust: use ? operator with Result");
  ("except", "Rust: use match on Result");
  (* Go patterns *)
  ("make", "Rust: use Vec::new() and push()");
  ("defer", "Rust: use Drop trait");
  ("interface", "Rust: use trait");
  ("nil", "Rust: use Option<T>::None");
  (* Ruby patterns *)
  ("puts", "Rust: use println!()");
  ("each", "Rust: use for item or .iter().for_each()");
  ("include", "Rust: use trait implementation");
  ("class", "Rust: use structs and impl");
]

let is_stdlib_name (name : string) =
  List.exists (fun prefix ->
    String.length name >= String.length prefix &&
    String.sub name 0 (String.length prefix) = prefix
  ) ["std::"; "core::"; "Vec::"; "String::"; "Option::"; "Result::"; "HashMap::"]

(* ── Main analysis ─────────────────────────────────────────────────── *)

let analyze_module (mod_ : Catseye_ast.Types.t) : finding list =
  let rec collect_apps (e : expr) : (string * int) list =
    match e.expr_value with
    | EApp (fn, args) ->
      let fn_name = match fn.expr_value with EVar n -> n | _ -> "" in
      (fn_name, e.expr_location.start.line) :: List.concat_map collect_apps args
    | EBlock es -> List.concat_map collect_apps es
    | ELet (_, e1, e2) -> collect_apps e1 @ collect_apps e2
    | EIf (_, t, o) -> collect_apps t @ (match o with Some e -> collect_apps e | None -> [])
    | ECase (_, bs) -> List.concat (List.map (fun (_, e) -> collect_apps e) bs)
    | EFn (_, b) -> collect_apps b
    | _ -> []
  in
  
  let walk_items (items : item list) : finding list =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        (* Check for inefficient patterns *)
        let rec check_inefficient (e : expr) : finding list =
          match e.expr_value with
          | EApp (fn, args) ->
            let fn_name = match fn.expr_value with EVar n -> n | _ -> "" in
            let line = e.expr_location.start.line in
            (* Extract method name from field expressions like data.clone or .unwrap *)
            let method_name = 
              if String.length fn_name > 1 && fn_name.[0] = '.' then
                Some (String.sub fn_name 1 (String.length fn_name - 1))
              else if String.length fn_name > 7 && 
                      String.sub fn_name (String.length fn_name - 6) 6 = ".clone" then
                Some "clone"
              else None
            in
            let results = (match method_name with
              | Some "clone" when not (is_stdlib_name fn_name) ->
                [{ rule_id = "RustInefficiency"; severity = Warning;
                   file = ""; line;
                   message = "Unnecessary .clone() - consider using references or avoiding move";
                   suggestion = Some "Pass by reference (&) or restructure to avoid clone" }]
              | _ -> []
            ) in
            results @ List.concat_map check_inefficient args
          | EBlock es -> List.concat_map check_inefficient es
          | ELet (_, e1, e2) -> check_inefficient e1 @ check_inefficient e2
          | EIf (_, t, o) -> check_inefficient t @ (match o with Some e -> check_inefficient e | None -> [])
          | ECase (_, bs) -> List.concat (List.map (fun (_, e) -> check_inefficient e) bs)
          | EFn (_, b) -> check_inefficient b
          | _ -> []
        in
        
        (* Check for hallucinated functions *)
        let apps = collect_apps body in
        let hall_findings = List.filter_map (fun (name, line) ->
          let clean = try
            let p = String.rindex name '.' in
            String.sub name (p + 1) (String.length name - p - 1)
          with _ -> name in
          match List.assoc_opt clean hallucinated_rust with
          | Some msg when not (is_stdlib_name name) ->
            Some { rule_id = "RustHallucination"; severity = Error;
                   file = ""; line; message = "AI hallucinated '" ^ clean ^ "'. " ^ msg;
                   suggestion = None }
          | _ -> None
        ) apps in
        
        (* Check for unsafe patterns *)
        let rec check_unsafe (e : expr) : finding list =
          match e.expr_value with
          | EApp (fn, args) ->
            let fn_name = match fn.expr_value with EVar n -> n | EApp _ -> "<nested>" | EBlock _ -> "<block>" | _ -> "" in
            let line = e.expr_location.start.line in
            (* Check for direct unsafe calls: unwrap(), expect(), panic!() *)
            let unsafe_patterns = ["unwrap"; "expect"; "unwrap_err"; "panic"; "todo"; "unimplemented"] in
            let found_unsafe = List.filter (fun n -> fn_name = n) unsafe_patterns in
            (* Check for method calls: result.unwrap(), option.expect() *)
            let found_method = 
              if fn_name <> "" && not (List.mem fn_name found_unsafe) then
                (* Check if fn_name ends with an unsafe pattern like .unwrap, .expect *)
                let rec check_patterns name patterns = match patterns with
                  | [] -> []
                  | p :: rest ->
                    if String.length name > String.length p + 1 &&
                       String.sub name (String.length name - String.length p - 1) (String.length p + 1) = ("." ^ p)
                    then p :: check_patterns name rest
                    else check_patterns name rest
                in
                check_patterns fn_name unsafe_patterns
              else [] in
            let () = if fn_name <> "" && (fn_name = "unwrap" || fn_name = "Result.unwrap" || fn_name = "option.unwrap" || fn_name = ".unwrap") then Printf.eprintf "DEBUG check: fn=%s found_unsafe=%d found_method=%d\n" fn_name (List.length found_unsafe) (List.length found_method) in
            let results = (List.map (fun _ ->
              { rule_id = "UnsafePanic"; severity = Error;
                file = ""; line; 
                message = "Unsafe: " ^ fn_name ^ "() may panic - consider proper error handling";
                suggestion = Some "Use ? operator, unwrap_or, or match pattern" }
            ) (found_unsafe @ found_method)) in
            results @ List.concat_map check_unsafe args
          | EBlock es -> List.concat_map check_unsafe es
          | ELet (_, e1, e2) -> check_unsafe e1 @ check_unsafe e2
          | EIf (_, t, o) -> check_unsafe t @ (match o with Some e -> check_unsafe e | None -> [])
          | ECase (_, bs) -> List.concat (List.map (fun (_, e) -> check_unsafe e) bs)
          | EFn (_, b) -> check_unsafe b
          | _ -> []
        in
        
        hall_findings @ check_unsafe body @ check_inefficient body
      | _ -> []
    ) items
  in
  
  walk_items mod_.mod_items
