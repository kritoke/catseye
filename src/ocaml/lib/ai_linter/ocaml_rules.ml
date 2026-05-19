(* src/ocaml/lib/ai_linter/ocaml_rules.ml
   OCaml-specific AST rules for antipattern and AI hallucination detection.
   
   Key areas:
   1. AI hallucinated functions (Haskell/Scala/Python APIs used in OCaml)
   2. Unsafe patterns: Obj.magic, Marshal.from_channel, unsafe operations
   3. Common mistakes: Option.get, partial functions, Printf without open
   4. Best practices: avoid exceptions, use Result, proper module structure
*)

open Catseye_ast.Types

module T = Types

(* ── Expression helpers ─────────────────────────────────────────────── *)

let rec expr_name (e : expr) : string =
  match e.expr_value with
  | EVar name -> name
  | EFieldAccess (recv, field) ->
    let prefix = expr_name recv in
    if prefix = "" then field else prefix ^ "." ^ field
  | _ -> ""

let rec collect_app_names (e : expr) : (string * int) list =
  match e.expr_value with
  | EApp (fn, args) ->
    let name = expr_name fn in
    (name, e.expr_location.start.line) :: List.concat_map collect_app_names (fn :: args)
  | EBlock es -> List.concat_map collect_app_names es
  | ELet (_, e1, e2) -> collect_app_names e1 @ collect_app_names e2
  | EIf (cond, then_, else_) ->
    collect_app_names cond @ collect_app_names then_ @
    (match else_ with Some e2 -> collect_app_names e2 | None -> [])
  | ECase (scrut, branches) ->
    collect_app_names scrut @ List.concat (List.map (fun (_, e) -> collect_app_names e) branches)
  | EFn (_, body) -> collect_app_names body
  | EFieldAccess (recv, _) -> collect_app_names recv
  | _ -> []

let rec walk_items_for_apps (items : item list) : (string * int) list =
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_app_names body
    | IConstant (_, _, body) -> collect_app_names body
    | IModule (_, subs) -> walk_items_for_apps subs
    | _ -> []
  ) items

(* ── 1. AI Hallucinated Functions ───────────────────────────────────── *)

type hallucination = {
  name : string;
  correct : string;
}

let hallucinated_ocaml : (string * hallucination) list = [
  (* Haskell patterns used in OCaml *)
  ("foldl",          { name = "foldl";          correct = "OCaml uses List.fold_left (args are reversed vs Haskell)" });
  ("foldr",          { name = "foldr";          correct = "OCaml uses List.fold_right" });
  ("mapM",           { name = "mapM";           correct = "OCaml uses List.map + combine, or a monadic library" });
  ("sequence",       { name = "sequence";       correct = "OCaml has no built-in sequence — use List.filter_map or a library" });
  ("liftM",          { name = "liftM";          correct = "OCaml doesn't have generic liftM — use Result.map or Option.map" });
  ("concatMap",      { name = "concatMap";      correct = "OCaml uses List.concat_map" });
  ("intersperse",    { name = "intersperse";    correct = "Not in stdlib — use String.concat or implement manually" });
  ("groupBy",        { name = "groupBy";        correct = "Not in stdlib — implement with List.fold_left" });
  ("sortBy",         { name = "sortBy";         correct = "OCaml uses List.sort with a comparison function" });
  ("filterM",        { name = "filterM";        correct = "No stdlib equivalent — implement with List.filter_map" });
  ("unless",         { name = "unless";         correct = "OCaml uses if not ... then ..." });
  ("when",           { name = "when";           correct = "OCaml uses if ... then () else ..." });
  ("mapM_",          { name = "mapM_";          correct = "OCaml: use List.iter for side effects" });
  ("forM",           { name = "forM";           correct = "OCaml: use List.map for mapping, List.iter for effects" });
  ("print",          { name = "print";          correct = "OCaml uses print_string, print_int, Printf.printf, etc." });
  ("putStrLn",       { name = "putStrLn";       correct = "OCaml uses print_endline" });
  ("getLine",        { name = "getLine";        correct = "OCaml uses read_line" });
  ("readFile",       { name = "readFile";       correct = "OCaml uses In_channel.with_open_in or Stdio.In_channel" });
  ("writeFile",      { name = "writeFile";      correct = "OCaml uses Out_channel.with_open_out" });
  ("head",           { name = "head";           correct = "OCaml uses List.hd (but prefer pattern matching)" });
  ("tail",           { name = "tail";           correct = "OCaml uses List.tl (but prefer pattern matching)" });
  ("init",           { name = "init";           correct = "OCaml uses List.init or Array.init" });
  ("length",         { name = "length";         correct = "OCaml uses List.length or Array.length or String.length" });
  ("reverse",        { name = "reverse";        correct = "OCaml uses List.rev" });
  ("take",           { name = "take";           correct = "Not in stdlib — use BatEnum.take or implement manually" });
  ("drop",           { name = "drop";           correct = "Not in stdlib — use List.filteri or implement manually" });
  ("zip",            { name = "zip";            correct = "OCaml uses List.combine" });
  ("unzip",          { name = "unzip";          correct = "OCaml uses List.split" });
  ("lookup",         { name = "lookup";         correct = "OCaml uses List.assoc or Hashtbl.find" });
  ("error",          { name = "error";          correct = "OCaml uses failwith or raise (Failure ...)" });
  ("throw",          { name = "throw";          correct = "OCaml uses raise (exception constructor)" });
  ("catch",          { name = "catch";          correct = "OCaml uses try ... with ... for exception handling" });
  ("let!",           { name = "let!";           correct = "OCaml uses let* or let+ for monadic binding (3.12+)" });
  ("do",             { name = "do";             correct = "OCaml doesn't have do notation — use let* bindings" });
  (* Python patterns *)
  ("range",          { name = "range";          correct = "OCaml: use Array.init or for loop" });
  ("len",            { name = "len";            correct = "OCaml uses List.length / Array.length / String.length" });
  ("enumerate",      { name = "enumerate";      correct = "OCaml: use List.mapi or List.iteri" });
  ("strip",          { name = "strip";          correct = "OCaml uses String.trim" });
  (* Scala/Java patterns *)
  ("println",        { name = "println";        correct = "OCaml uses print_endline or Printf.printf" });
  ("asInstanceOf",   { name = "asInstanceOf";   correct = "OCaml doesn't have runtime type casts — use pattern matching" });
  ("isInstanceOf",   { name = "isInstanceOf";   correct = "OCaml uses polymorphic variant tests or pattern matching" });
  ("match",          { name = "match";          correct = "OCaml uses match ... with (not match ... =>)" });
  ("def",            { name = "def";            correct = "OCaml uses let for function definitions" });
  ("val",            { name = "val";            correct = "OCaml uses let for bindings (val is for signatures)" });
]

let hallucination_map : (string, hallucination) Hashtbl.t =
  let tbl = Hashtbl.create 64 in
  List.iter (fun (_, e) -> Hashtbl.add tbl e.name e) hallucinated_ocaml;
  tbl

(* ── 2. Unsafe Patterns ────────────────────────────────────────────── *)

let check_unsafe (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "Obj.magic" ->
      Some { T.file = path; line; rule_id = "unsafe-obj-magic";
        severity = T.Error;
        message = "Obj.magic bypasses the type system — extremely unsafe";
        suggestion = Some "Refactor to use proper types, GADTs, or polymorphic variants" }
    | "Obj.set_field" | "Obj.obj" | "Obj.dup" | "Obj.truncate" ->
      Some { T.file = path; line; rule_id = "unsafe-obj";
        severity = T.Error;
        message = Printf.sprintf "%s is an unsafe Obj operation that can corrupt memory" name;
        suggestion = Some "Use safe alternatives — ref cells, arrays, or proper data structures" }
    | "Marshal.from_channel" | "Marshal.from_string" ->
      Some { T.file = path; line; rule_id = "unsafe-deserialization";
        severity = T.Warning;
        message = Printf.sprintf "%s can deserialize arbitrary OCaml values — security risk" name;
        suggestion = Some "Use typed parsing (yojson, atdgen) or validate input first" }
    | "Marshal.to_channel" | "Marshal.to_string" ->
      Some { T.file = path; line; rule_id = "unsafe-serialization";
        severity = T.Hint;
        message = Printf.sprintf "%s serializes closures and custom blocks — may leak data" name;
        suggestion = Some "Prefer typed serialization (yojson, bin_prot)" }
    | "Sys.command" ->
      Some { T.file = path; line; rule_id = "command-injection";
        severity = T.Error;
        message = "Sys.command() executes shell commands — command injection risk";
        suggestion = Some "Use Sys.argv or a proper argument array, not shell strings" }
    | "Unix.exec" | "Unix.execv" | "Unix.execvp" | "Unix.execve" ->
      Some { T.file = path; line; rule_id = "command-exec";
        severity = T.Warning;
        message = Printf.sprintf "%s replaces the process — ensure arguments are sanitized" name;
        suggestion = Some "Validate all arguments before exec" }
    | "open_in" | "open_out" ->
      Some { T.file = path; line; rule_id = "unchecked-file-access";
        severity = T.Hint;
        message = Printf.sprintf "%s opens a file — ensure path is validated and handle errors" name;
        suggestion = Some "Use with_open_in / with_open_out for automatic cleanup" }
    | _ -> None
  ) all_apps

(* ── 3. Common Mistakes ────────────────────────────────────────────── *)

let check_common_mistakes (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "Option.get" ->
      Some { T.file = path; line; rule_id = "partial-function";
        severity = T.Warning;
        message = "Option.get raises Invalid_argument on None — use pattern matching instead";
        suggestion = Some "Use match ... with Some x -> ... | None -> ... or Option.value ~default" }
    | "List.hd" ->
      Some { T.file = path; line; rule_id = "partial-function";
        severity = T.Warning;
        message = "List.hd raises Failure on empty list — use pattern matching";
        suggestion = Some "Use match ... with [] -> ... | x :: _ -> ..." }
    | "List.tl" ->
      Some { T.file = path; line; rule_id = "partial-function";
        severity = T.Warning;
        message = "List.tl raises Failure on empty list — use pattern matching";
        suggestion = Some "Use match ... with [] -> ... | _ :: rest -> ..." }
    | "List.find" ->
      Some { T.file = path; line; rule_id = "partial-function";
        severity = T.Hint;
        message = "List.find raises Not_found — consider List.find_opt for safety";
        suggestion = Some "Use List.find_opt to get 'a option instead of raising" }
    | "List.assoc" ->
      Some { T.file = path; line; rule_id = "partial-function";
        severity = T.Hint;
        message = "List.assoc raises Not_found — consider List.assoc_opt";
        suggestion = Some "Use List.assoc_opt for safe lookup" }
    | "failwith" | "invalid_arg" ->
      Some { T.file = path; line; rule_id = "exception-usage";
        severity = T.Hint;
        message = Printf.sprintf "%s raises an exception — consider using Result type for error handling" name;
        suggestion = Some "Return Result.t (Ok/Error) instead of throwing exceptions" }
    | "raise" ->
      Some { T.file = path; line; rule_id = "exception-usage";
        severity = T.Hint;
        message = "Exceptions are for truly exceptional cases — consider Result for expected errors";
        suggestion = Some "Use Result.t for expected error conditions" }
    | "Array.set" | "Array.get" ->
      Some { T.file = path; line; rule_id = "bounds-check";
        severity = T.Hint;
        message = Printf.sprintf "%s can raise Invalid_argument for out-of-bounds access" name;
        suggestion = Some "Check bounds before access, or use safe iteration" }
    | "Hashtbl.find" ->
      Some { T.file = path; line; rule_id = "partial-function";
        severity = T.Hint;
        message = "Hashtbl.find raises Not_found — consider Hashtbl.find_opt";
        suggestion = Some "Use Hashtbl.find_opt for safe lookup" }
    | "String.concat" ->
      None  (* Valid *)
    | _ -> None
  ) all_apps

(* ── 4. Best Practices ─────────────────────────────────────────────── *)

let check_best_practices (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "Printf.printf" ->
      Some { T.file = path; line; rule_id = "format-string";
        severity = T.Hint;
        message = "Printf.printf needs `open Printf` — ensure the module is opened or use fully qualified name";
        suggestion = Some "Add `open Printf` at the top, or use Printf.printf fully qualified" }
    | "Array.make" ->
      None  (* Valid but worth noting if used with mutable contents *)
    | "ref" ->
      None  (* Valid — OCaml's mutable references *)
    | _ -> None
  ) all_apps

(* ── 5. Hardcoded Secrets ──────────────────────────────────────────── *)

let is_secret_var (name : string) : bool =
  let lower = String.lowercase_ascii name in
  let starts_with prefix str =
    let plen = String.length prefix in
    String.length str >= plen && String.sub str 0 plen = prefix
  in
  List.exists (starts_with lower) [
    "password"; "secret"; "api_key"; "apikey"; "token"; "access_token";
    "private_key"; "auth_token"; "client_secret";
  ]

let rec check_hardcoded_secrets (items : item list) (path : string) : T.finding list =
  List.concat_map (fun item ->
    match item.item_value with
    | IConstant (PVar name, _, value) when is_secret_var name ->
      (match value.expr_value with
       | ELiteral (LString s) when String.length s > 4 ->
         [{ T.file = path; line = item.item_location.start.line;
            rule_id = "hardcoded-secrets"; severity = T.Warning;
            message = Printf.sprintf "Hardcoded secret in variable '%s'" name;
            suggestion = Some "Use environment variables via Sys.getenv" }]
       | _ -> [])
    | IModule (_, subs) -> check_hardcoded_secrets subs path
    | _ -> []
  ) items

(* ── 6. Todo / FIXME in code ──────────────────────────────────────── *)

(** Detect calls to `todo` function pattern in OCaml.
    OCaml doesn't have a built-in todo, but AI often generates `let todo = ...`
    or raises Failure "todo". Also flag `failwith "TODO" patterns. *)
let check_todo (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "todo" ->
      Some { T.file = path; line; rule_id = "todo-in-code";
        severity = T.Warning;
        message = "todo placeholder found — implement or remove before production";
        suggestion = Some "Implement the function or raise a more specific exception" }
    | _ -> None
  ) all_apps

(* ── 7. Unused let binding (OCaml-specific) ────────────────────────── *)

let rec collect_vars_in_expr (e : expr) : string list =
  match e.expr_value with
  | EVar v -> [v]
  | EApp (fn, args) -> collect_vars_in_expr fn @ List.concat_map collect_vars_in_expr args
  | EBlock es -> List.concat_map collect_vars_in_expr es
  | ELet (_, e1, e2) -> collect_vars_in_expr e1 @ collect_vars_in_expr e2
  | EIf (cond, then_, else_) ->
    collect_vars_in_expr cond @ collect_vars_in_expr then_
    @ (match else_ with Some e -> collect_vars_in_expr e | None -> [])
  | ECase (_, branches) ->
    List.concat_map (fun (_, body) -> collect_vars_in_expr body) branches
  | EFn (_, body) -> collect_vars_in_expr body
  | EBinOp (e1, _, e2) -> collect_vars_in_expr e1 @ collect_vars_in_expr e2
  | ETuple es | EList es -> List.concat_map collect_vars_in_expr es
  | ERecord fields -> List.concat_map (fun (_, v) -> collect_vars_in_expr v) fields
  | EFieldAccess (inner, _) -> collect_vars_in_expr inner
  | EAssignment (e1, e2) -> collect_vars_in_expr e1 @ collect_vars_in_expr e2
  | EUnOp (_, e) -> collect_vars_in_expr e
  | _ -> []

let rec find_unused_lets (e : expr) : (string * int) list =
  match e.expr_value with
  | ELet (PVar name, _, body) ->
    let used = collect_vars_in_expr body in
    let is_used = List.mem name used in
    let self = if not is_used && String.length name > 1 && name <> "_" then
      [(name, e.expr_location.start.line)] else [] in
    self @ find_unused_lets body
  | EBlock es -> List.concat_map find_unused_lets es
  | ELet (_, e1, e2) -> find_unused_lets e1 @ find_unused_lets e2
  | EIf (_, then_, else_) ->
    find_unused_lets then_ @ (match else_ with Some e -> find_unused_lets e | None -> [])
  | ECase (_, branches) ->
    List.concat_map (fun (_, body) -> find_unused_lets body) branches
  | EApp (fn, args) -> find_unused_lets fn @ List.concat_map find_unused_lets args
  | EFn (_, body) -> find_unused_lets body
  | _ -> []

let check_unused_lets (items : item list) (path : string) : T.finding list =
  let rec walk (items : item list) : T.finding list =
    List.concat_map (fun (item : item) ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.map (fun (name, line) ->
          { T.file = path; line; rule_id = "unused-binding";
            severity = T.Hint;
            message = Printf.sprintf "let binding '%s' is never used" name;
            suggestion = Some ("Remove unused binding or prefix with _ to indicate intentional discard") }
        ) (find_unused_lets body)
      | IModule (_, subs) -> walk subs
      | _ -> []
    ) items
  in
  walk items

(* ── 8. Verbose Option Pattern ──────────────────────────────────────── *)

(** Detect nested pattern matching on option types where let* would be cleaner *)
let count_option_matches (e : expr) : int =
  let rec count (depth : int) (e : expr) : int =
    match e.expr_value with
    | ECase (scrut, branches) ->
      (* Check if this is matching on an option *)
      let scrut_is_option = 
        match scrut.expr_value with
        | EApp (fn, _) -> 
          let name = expr_name fn in
          String.length name > 0 && (name = "Some" || name = "Option.some" ||
            String.ends_with ~suffix:".some" name || name = "Some")
        | _ -> false
      in
      if scrut_is_option then
        let child_max = List.fold_left (fun acc (_, body) -> max acc (count (depth + 1) body)) 0 branches in
        depth + child_max
      else
        List.fold_left (fun acc (_, body) -> max acc (count depth body)) 0 branches
    | EBlock es -> List.fold_left (fun acc x -> max acc (count depth x)) 0 es
    | ELet (_, e1, e2) -> max (count depth e1) (count depth e2)
    | EIf (_, then_, else_) -> 
      max (count depth then_) (match else_ with Some e -> count depth e | None -> 0)
    | _ -> 0
  in
  count 1 e

let check_verbose_option (items : item list) (path : string) : T.finding list =
  let rec check (e : expr) : (string * int) list =
    match e.expr_value with
    | ECase (_, branches) ->
      let count = count_option_matches e in
      let self = if count >= 2 then [(Printf.sprintf "Nested option matching (depth %d) — consider let*" count, e.expr_location.start.line)] else [] in
      self @ List.concat_map (fun (_, body) -> check body) branches
    | EBlock es -> List.concat_map check es
    | ELet (_, e1, e2) -> check e1 @ check e2
    | EIf (_, then_, else_) -> check then_ @ (match else_ with Some x -> check x | None -> [])
    | EFn (_, body) -> check body
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.map (fun (msg, line) ->
        { T.file = path; line; rule_id = "ocaml-verbose-option";
          severity = T.Hint;
          message = msg;
          suggestion = Some "Use let* for cleaner option handling" }
      ) (check body)
    | _ -> []
  ) items

(* ── 9. Non-tail Recursive Functions ───────────────────────────────── *)

let rec find_recursive_calls (name : string) (e : expr) : int list =
  match e.expr_value with
  | EApp (fn, _) when expr_name fn = name ->
    [e.expr_location.start.line]
  | ECase (_, branches) -> List.concat_map (fun (_, body) -> find_recursive_calls name body) branches
  | EIf (_, then_, else_) ->
    find_recursive_calls name then_ @ (match else_ with Some e -> find_recursive_calls name e | None -> [])
  | ELet (_, e1, e2) -> find_recursive_calls name e1 @ find_recursive_calls name e2
  | EBlock es -> List.concat_map (find_recursive_calls name) es
  | EFn (_, body) -> find_recursive_calls name body
  | _ -> []

let check_non_tail_recursive (items : item list) (path : string) : T.finding list =
  let rec analyze_fn (name : string) (body : expr) : T.finding option =
    let calls = find_recursive_calls name body in
    if List.length calls > 3 && not (is_simple_tail_recursive body name) then
      Some { T.file = path; line = body.expr_location.start.line; 
            rule_id = "ocaml-non-tail-recursive";
            severity = T.Warning;
            message = Printf.sprintf "Function '%s' has %d recursive calls — ensure tail-recursive for large inputs" name (List.length calls);
            suggestion = Some "Use accumulator parameter for tail recursion" }
    else None
  and is_simple_tail_recursive (e : expr) (name : string) : bool =
    match e.expr_value with
    | EIf (_, then_, else_) ->
      is_simple_tail_recursive then_ name && 
      (match else_ with Some e -> is_simple_tail_recursive e name | None -> true)
    | ELet (_, _, body) -> is_simple_tail_recursive body name
    | ECase (_, branches) -> 
      List.for_all (fun (_, body) -> is_simple_tail_recursive body name) branches
    | EBlock es -> (match List.rev es with [] -> true | last :: _ -> is_simple_tail_recursive last name)
    | EApp (fn, _) -> expr_name fn = name  (* Direct tail call *)
    | _ -> false
  in
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) when String.length name > 0 && name.[0] <> '_' ->
      analyze_fn name body
    | _ -> None
  ) items

(* ── 10. Redundant Boolean Comparison ────────────────────────────────── *)

(** Detect patterns like `if x = y then true else false` which should be `x = y` *)
let check_redundant_bool (items : item list) (path : string) : T.finding list =
  let rec find_bool_comparisons (e : expr) : (string * int) list =
    match e.expr_value with
    | EIf (cond, then_e, else_e) ->
      let self = (match then_e.expr_value, else_e with
       | ELiteral (LString "True"), Some x when x.expr_value = ELiteral (LString "False") ->
         [(expr_name cond, e.expr_location.start.line)]
       | ELiteral (LString "False"), Some x when x.expr_value = ELiteral (LString "True") ->
         [(expr_name cond, e.expr_location.start.line)]
       | _ -> []) in
      self @ find_bool_comparisons then_e @ (match else_e with Some x -> find_bool_comparisons x | None -> [])
    | EBlock es -> List.concat_map find_bool_comparisons es
    | ELet (_, e1, e2) -> find_bool_comparisons e1 @ find_bool_comparisons e2
    | ECase (_, branches) -> List.concat_map (fun (_, body) -> find_bool_comparisons body) branches
    | EFn (_, body) -> find_bool_comparisons body
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.map (fun (cond, line) ->
        { T.file = path; line; rule_id = "ocaml-redundant-if-bool";
          severity = T.Hint;
          message = Printf.sprintf "Redundant 'if %s then true else false' — just use '%s'" cond cond;
          suggestion = Some "Use the boolean expression directly" }
      ) (find_bool_comparisons body)
    | _ -> []
  ) items

(* ── Main analyzer ─────────────────────────────────────────────────── *)

let analyze_module (mod_ : Catseye_ast.Types.t) : T.finding list =
  let all_apps = walk_items_for_apps mod_.mod_items in
  let path = mod_.mod_path in

  (* Hallucinated methods *)
  let hallucination_findings = List.filter_map (fun (name, line) ->
    let last = try let i = String.rindex name '.' in String.sub name (i+1) (String.length name - i - 1) with Not_found -> name in
    match (Hashtbl.find_opt hallucination_map name, Hashtbl.find_opt hallucination_map last) with
    | Some entry, _ | _, Some entry ->
      Some { T.file = path; line; rule_id = "hallucinated-method";
        severity = T.Warning;
        message = Printf.sprintf "'%s' doesn't exist in OCaml — %s" name entry.correct;
        suggestion = Some entry.correct }
    | None, None -> None
  ) all_apps in

  hallucination_findings
  @ check_unsafe all_apps path
  @ check_common_mistakes all_apps path
  @ check_best_practices all_apps path
  @ check_hardcoded_secrets mod_.mod_items path
  @ check_todo all_apps path
  @ check_unused_lets mod_.mod_items path
  @ check_verbose_option mod_.mod_items path
  @ check_non_tail_recursive mod_.mod_items path
  @ check_redundant_bool mod_.mod_items path
