(* src/ocaml/lib/ai_linter/nim_rules.ml
   Nim-specific AST rules for antipattern and security detection.

   Key areas:
   1. Bare except: without exception type
   2. Deprecated nil usage (prefer none/default)
   3. Missing raises pragma on public procs
   4. Unchecked execCmd/execShellCmd (command injection)
   5. Long methods and complexity
   6. AI hallucinated functions (Python/Ruby/JS APIs in Nim)
 *)

include Crystal_rules_helpers
open Catseye_ast.Types
open Types

(* ── Helpers ──────────────────────────────────────────────────────── *)

let is_test_file (file : string) : bool =
  let lower = String.lowercase_ascii file in
  name_ends_with_any lower ["_test.nim"; "_tests.nim"; "test.nim"]

(* ── Recursive app collector ──────────────────────────────────────── *)

let rec collect_apps (e : expr) : (string * int) list =
  match e.expr_value with
  | EApp (fn, args) ->
    let fn_name = expr_name fn in
    (fn_name, e.expr_location.start.line) :: List.concat_map collect_apps (fn :: args)
  | EBlock es -> List.concat_map collect_apps es
  | ELet (_, e1, e2) -> collect_apps e1 @ collect_apps e2
  | EIf (_, t, o) -> collect_apps t @ (match o with Some e -> collect_apps e | None -> [])
  | ECase (_, bs) -> List.concat (List.map (fun (_, e) -> collect_apps e) bs)
  | EFn (_, b) -> collect_apps b
  | EFieldAccess (r, _) -> collect_apps r
  | EBinOp (l, _, r) -> collect_apps l @ collect_apps r
  | EUnOp (_, x) -> collect_apps x
  | EAssignment (l, r) -> collect_apps l @ collect_apps r
  | ETuple es | EList es -> List.concat_map collect_apps es
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; _ } ->
    collect_apps try_body
    @ List.concat_map (fun rc -> collect_apps rc.rescue_body) rescue_clauses
    @ (match ensure_body with Some e -> collect_apps e | None -> [])
  | _ -> []

(* ── Hallucinated Functions Detection ─────────────────────────────── *)

let hallucinated_nim = [
  (* Python patterns. NOTE: names that ARE valid Nim (len, map, filter, sorted,
     enumerate, zip from system/sequtils/algorithm) are deliberately ABSENT —
     flagging them produced false positives on idiomatic code. Only names that
     do not exist in the Nim stdlib appear here. *)
  ("print", "Nim: use echo() or stdout.write()");
  ("input", "Nim: use stdin.readLine()");
  ("range", "Nim: use 0..<n or countup(0, n)");
  ("type", "Nim: use type keyword, not function");
  ("list", "Nim: use seq[T] or array[N, T]");
  ("dict", "Nim: use Table[K, V] or OrderedTable[K, V]");
  ("str", "Nim: use $ or $variable");
  ("reduce", "Nim: use foldl from std/sequtils");
  ("isinstance", "Nim: use `of` operator or `is` operator");
  ("hasattr", "Nim: use `hasKey` for tables or check field existence");
  ("lambda", "Nim: use proc(x: int): int = x + 1");
  ("yield", "Nim: use iterator with yield statement");
  ("global", "Nim: use global pragma or module-level var");
  (* Python string-method lookalikes (Nim names differ: startsWith/endsWith/toLowerAscii…) *)
  ("startswith", "Nim: use startsWith(x, prefix)");
  ("endswith", "Nim: use endsWith(x, suffix)");
  ("lower", "Nim: use toLowerAscii()");
  ("upper", "Nim: use toUpperAscii()");
  ("title", "Nim: use capitalize() or capitalizeAscii()");
  (* Python dict/list-method lookalikes *)
  ("dict.get", "Nim: use m.getOrDefault(key) or m[].getOrDefault(key)");
  ("dict.keys", "Nim: use keys(m) from std/tables");
  ("dict.values", "Nim: use values(m) from std/tables");
  ("dict.items", "Nim: use pairs(m) from std/tables");
  ("set.add", "Nim: use incl(s, x) for sets");
  ("str.format", "Nim: use strformat fmt or the & operator");
  ("list.append", "Nim: use add(seq, x)");
  ("list.extend", "Nim: use seq.add(other)");
  ("list.index", "Nim: use find() or a for-loop over pairs()");
  ("list.pop", "Nim: use seq.pop() (returns last) or delete(seq, i)");
  (* JavaScript patterns *)
  ("console.log", "Nim: use echo() or debugEcho()");
  ("console.error", "Nim: use stderr.writeLine()");
  ("document.getElementById", "Nim: not applicable (no DOM in Nim)");
  ("Array.isArray", "Nim: use `x is seq` or `x is array`");
  ("Array.includes", "Nim: use contains(seq, x)");
  ("String.includes", "Nim: use contains(s, sub)");
  ("JSON.parse", "Nim: use parseJson() from std/json");
  ("JSON.stringify", "Nim: use toJson() from std/json");
  ("Number.parseInt", "Nim: use parseInt() from std/strutils");
  ("setTimeout", "Nim: use os.sleep() or asyncdispatch");
  ("fetch", "Nim: use httpclient get/post or getContent()");
  ("require", "Nim: use import statement");
  ("module.exports", "Nim: export symbols with * or export statement");
  ("process.env", "Nim: use os.getEnv()");
  ("process.exit", "Nim: use quit()");
  (* Ruby patterns *)
  ("puts", "Nim: use echo()");
  ("gets", "Nim: use stdin.readLine()");
  ("each", "Nim: use for x in collection:");
  ("each_with_index", "Nim: use pairs() or mpairs()");
  ("select", "Nim: use filter() from std/sequtils");
  ("size", "Nim: use len()");
  ("attr_accessor", "Nim: use object fields with getters/setters");
  (* Go patterns *)
  ("fmt.Println", "Nim: use echo()");
  ("fmt.Sprintf", "Nim: use strformat fmt or the & operator");
  ("strings.Contains", "Nim: use contains() from std/strutils");
  ("strings.Split", "Nim: use split() from std/strutils");
  ("http.Get", "Nim: use httpclient getContent/get");
  ("time.Now", "Nim: use times.now()");
  ("make", "Nim: use @[] for seq or newSeq()");
  ("append", "Nim: use add() or &= for seq");
  ("goroutine", "Nim: use spawn from std/threadpool or async");
  ("chan", "Nim: use Channel[T] from std/channels");
  ("nil", "Nim: use nil (but prefer Option[T] with none)");
  (* Async idioms *)
  ("async", "Nim: use the {.async.} pragma on procs, not an async() call");
]

(* ── Rule: Bare except ────────────────────────────────────────────── *)

let rec detect_bare_except (e : expr) : (int * string) list =
  match e.expr_value with
  | ETryCatchFinally { rescue_clauses; _ } ->
    let bare = List.filter_map (fun (rc : rescue_clause) ->
      if rc.matched_types = [] then
        Some (rc.rescue_body.expr_location.start.line, "bare except: without exception type — use except SpecificError:")
      else None
    ) rescue_clauses in
    let nested = List.concat_map (fun (rc : rescue_clause) -> detect_bare_except rc.rescue_body) rescue_clauses in
    bare @ nested
  | EBlock es -> List.concat_map detect_bare_except es
  | ELet (_, e1, e2) -> detect_bare_except e1 @ detect_bare_except e2
  | EIf (_, t, o) -> detect_bare_except t @ (match o with Some e -> detect_bare_except e | None -> [])
  | ECase (_, bs) -> List.concat (List.map (fun (_, e) -> detect_bare_except e) bs)
  | EFn (_, b) -> detect_bare_except b
  | _ -> []

(* ── Rule: Long method detection ──────────────────────────────────── *)

let rec count_statements (e : expr) : int =
  match e.expr_value with
  | EBlock es -> List.fold_left (+) 0 (List.map count_statements es)
  | ELet (_, e1, e2) -> 1 + count_statements e1 + count_statements e2
  | EIf (_, t, o) -> 1 + count_statements t + (match o with Some e -> count_statements e | None -> 0)
  | ECase (_, bs) -> 1 + List.fold_left (+) 0 (List.map (fun (_, e) -> count_statements e) bs)
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; _ } ->
    1 + count_statements try_body
    + List.fold_left (+) 0 (List.map (fun rc -> count_statements rc.rescue_body) rescue_clauses)
    + (match ensure_body with Some e -> count_statements e | None -> 0)
  | EFn (_, b) -> count_statements b
  | _ -> 1

(* ── Rule: Unsafe conversion outside try/except ──────────────────────
   From Nim Tips: parseEnum/parseInt/parseFloat/parseJson raise on bad input.
   Flag them when called outside a try/except handler. *)

let unsafe_parsers = [
  "parseJson"; "parseInt"; "parseFloat"; "parseEnum"; "parseBiggestInt"; "parseUInt";
  "json.parseJson"; "strutils.parseInt"; "strutils.parseFloat"; "strutils.parseEnum";
]

let is_unsafe_parser name =
  List.exists (fun p -> name = p || String.ends_with ~suffix:("." ^ p) name) unsafe_parsers

(** Walk an expression, tracking whether we're inside a try/except.
    Returns (line, name) pairs for unsafe parser calls NOT inside a try. *)
let rec collect_unsafe_outside_try ~in_try (e : expr) : (int * string) list =
  match e.expr_value with
  | EApp (fn, args) ->
    let fn_name = expr_name fn in
    let here = if (not in_try) && is_unsafe_parser fn_name then
      [(e.expr_location.start.line, fn_name)]
    else [] in
    here @ List.concat_map (fun a -> collect_unsafe_outside_try ~in_try a) args
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; _ } ->
    (* Inside the try body, parser calls are considered safe *)
    collect_unsafe_outside_try ~in_try:true try_body
    @ List.concat_map (fun rc -> collect_unsafe_outside_try ~in_try rc.rescue_body) rescue_clauses
    @ (match ensure_body with Some e -> collect_unsafe_outside_try ~in_try e | None -> [])
  | EBlock es -> List.concat_map (fun x -> collect_unsafe_outside_try ~in_try x) es
  | ELet (_, e1, e2) -> collect_unsafe_outside_try ~in_try e1 @ collect_unsafe_outside_try ~in_try e2
  | EIf (_, t, o) -> collect_unsafe_outside_try ~in_try t @ (match o with Some e -> collect_unsafe_outside_try ~in_try e | None -> [])
  | ECase (_, bs) -> List.concat_map (fun (_, x) -> collect_unsafe_outside_try ~in_try x) bs
  | EFn (_, b) -> collect_unsafe_outside_try ~in_try b
  | EBinOp (a, _, b) -> collect_unsafe_outside_try ~in_try a @ collect_unsafe_outside_try ~in_try b
  | EUnOp (_, a) -> collect_unsafe_outside_try ~in_try a
  | EAssignment (a, b) -> collect_unsafe_outside_try ~in_try a @ collect_unsafe_outside_try ~in_try b
  | _ -> []

(* ── Rule: Unchecked dangerous calls ──────────────────────────────── *)

let dangerous_calls = [
  ("execCmd", "execCmd result (exit code) is not checked — consider using execProcess or checking return value");
  ("execShellCmd", "execShellCmd result is not checked — command injection risk with user input");
  ("startProcess", "startProcess without proper input validation — command injection risk");
]

(* ── Rule: Unused parameters ───────────────────────────────────────── *)

(** Collect every EVar name appearing anywhere in an expression. *)
let rec collect_var_names (e : expr) (acc : string list) : string list =
  let acc = match e.expr_value with
    | EVar v -> if List.mem v acc then acc else v :: acc
    | _ -> acc
  in
  match e.expr_value with
  | EApp (fn, args) ->
    collect_var_names fn acc |> fun a ->
    List.fold_left (fun a x -> collect_var_names x a) a args
  | EBlock es -> List.fold_left (fun a x -> collect_var_names x a) acc es
  | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
    collect_var_names e1 acc |> collect_var_names e2
  | EIf (c, t, o) ->
    collect_var_names c acc |> collect_var_names t |> fun a ->
    (match o with Some x -> collect_var_names x a | None -> a)
  | ECase (s, bs) -> collect_var_names s acc |> fun a ->
    List.fold_left (fun a (_, b) -> collect_var_names b a) a bs
  | EFn (_, b) -> collect_var_names b acc
  | EBinOp (l, _, r) -> collect_var_names l acc |> collect_var_names r
  | EUnOp (_, x) -> collect_var_names x acc
  | EAssignment (l, r) -> collect_var_names l acc |> collect_var_names r
  | ETuple es | EList es -> List.fold_left (fun a x -> collect_var_names x a) acc es
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; _ } ->
    collect_var_names try_body acc |> fun a ->
    List.fold_left (fun a rc -> collect_var_names rc.rescue_body a) a rescue_clauses |> fun a ->
    (match ensure_body with Some x -> collect_var_names x a | None -> a)
  | _ -> acc

(** Split a parameter pattern name — the Nim mapper joins multi-declarations
    ("a, b") into one PVar. *)
let param_names (params : pattern list) : string list =
  List.concat_map (fun p ->
    match p with
    | PVar n ->
      List.map String.trim (String.split_on_char ',' n)
      |> List.filter (fun s -> s <> "" && s <> "_")
    | _ -> []) params

let detect_unused_params (params : pattern list) (body : expr) : string list =
  let used = collect_var_names body [] in
  param_names params
  |> List.filter (fun p -> not (List.mem p used))

(* ── Rule: Shadowed variables ────────────────────────────────────── *)

(** Inner let/var rebinding an outer in-scope name within the same proc.
    Sequential block scope: later statements see earlier bindings. *)
let detect_shadowed_vars (e : expr) : (int * string) list =
  let rec go bound e =
    match e.expr_value with
    | ELet (PVar n, rhs, body) when n <> "_" ->
      let self = if List.mem n bound then [(e.expr_location.start.line, n)] else [] in
      self @ go bound rhs @ go (n :: bound) body
    | ELet (p, rhs, body) -> go bound rhs @ go bound body @ (ignore p; [])
    | EBlock es ->
      let _, found =
        List.fold_left (fun (b, acc) s ->
          let hits = go b s in
          let b' = match s.expr_value with
            | ELet (PVar n, _, _) when n <> "_" -> n :: b
            | _ -> b
          in
          (b', acc @ hits)) (bound, []) es
      in found
    | EIf (c, t, o) ->
      go bound c @ go bound t @ (match o with Some x -> go bound x | None -> [])
    | ECase (s, bs) -> go bound s @ List.concat_map (fun (_, b) -> go bound b) bs
    | EFn (_, b) -> go bound b
    | ETryCatchFinally { try_body; rescue_clauses; ensure_body; _ } ->
      go bound try_body
      @ List.concat_map (fun rc -> go bound rc.rescue_body) rescue_clauses
      @ (match ensure_body with Some x -> go bound x | None -> [])
    | _ -> []
  in go [] e

(* ── Rule: Empty rescue (except body only discard) ─────────────────── *)

let rec detect_empty_rescue (e : expr) : int list =
  match e.expr_value with
  | ETryCatchFinally { try_body; rescue_clauses; _ } ->
    let empties =
      List.filter_map (fun (rc : rescue_clause) ->
        let only_discard = match rc.rescue_body.expr_value with
          | EUnit -> true
          | EBlock [] -> true
          | EBlock [{ expr_value = EUnit; _ }] -> true
          | _ -> false
        in
        if only_discard then Some rc.rescue_body.expr_location.start.line else None)
        rescue_clauses
    in
    empties
    @ detect_empty_rescue try_body
    @ List.concat_map (fun rc -> detect_empty_rescue rc.rescue_body) rescue_clauses
  | EBlock es -> List.concat_map detect_empty_rescue es
  | ELet (_, e1, e2) -> detect_empty_rescue e1 @ detect_empty_rescue e2
  | EIf (c, t, o) -> detect_empty_rescue c @ detect_empty_rescue t
                      @ (match o with Some x -> detect_empty_rescue x | None -> [])
  | ECase (s, bs) -> detect_empty_rescue s @ List.concat_map (fun (_, b) -> detect_empty_rescue b) bs
  | EFn (_, b) -> detect_empty_rescue b
  | _ -> []

(* ── Rule: Debug leftovers ────────────────────────────────────── *)

let detect_debug_leftover (apps : (string * int) list) : int list =
  List.filter_map (fun (n, line) ->
    if n = "debugEcho" || String.ends_with ~suffix:".debugEcho" n then Some line
    else None) apps

(* ── Rule: Deprecated APIs ────────────────────────────────────────── *)

let deprecated_apis = [
  ("existsFile", "fileExists");
  ("existsDir", "dirExists");
  ("os.existsFile", "os.fileExists");
  ("os.existsDir", "os.dirExists");
  ("strutils.format", "std/strformat: fmt or the & operator");
  ("format", "std/strformat: fmt or the & operator");
  ("writeln", "echo() or writeLine(stdout, …)");
  ("system.writeln", "echo() or writeLine(stdout, …)");
]

(* ── Rule: Mass assignment from parsed JSON ────────────────────────── *)

(** `x.to(Type)` where x was assigned from parseJson in the same proc —
    untrusted JSON deserialized wholesale into an object. *)
let detect_mass_assignment (e : expr) : int list =
  let is_parse_json (n : string) =
    n = "parseJson" || String.ends_with ~suffix:".parseJson" n
    || n = "json.parseJson" in
  (* Thread json-tainted vars through statement blocks: the mapper emits each
     `let` as ELet(…, EUnit) with subsequent statements as SIBLINGS, so the
     block must fold state forward. *)
  let rec go json_vars e =
    match e.expr_value with
    | EBlock es ->
      Stdlib.List.fold_left (fun (jv, acc) s ->
        let jv' = match s.expr_value with
          | ELet (PVar v, { expr_value = EApp (fn, _); _ }, _)
            when is_parse_json (expr_name fn) -> v :: jv
          | _ -> jv
        in
        (jv', acc @ go jv' s)) (json_vars, []) es
      |> snd
    | EApp (fn, args) ->
      let self =
        (match fn.expr_value with
         | EFieldAccess ({ expr_value = EVar recv; _ }, "to")
           when Stdlib.List.mem recv json_vars -> [e.expr_location.start.line]
         | _ -> [])
      in
      self @ List.fold_left (fun a x -> a @ go json_vars x) [] (fn :: args)
    | ELet (PVar v, rhs, body) ->
      let jv = match rhs.expr_value with
        | EApp (fn, _) when is_parse_json (expr_name fn) -> v :: json_vars
        | _ -> json_vars
      in
      go jv body @ go json_vars rhs
    | EIf (c, t, o) -> go json_vars c @ go json_vars t
                          @ (match o with Some x -> go json_vars x | None -> [])
    | ECase (s, bs) -> go json_vars s @ List.concat_map (fun (_, b) -> go json_vars b) bs
    | EFn (_, b) -> go json_vars b
    | EAssignment (l, r) -> go json_vars l @ go json_vars r
    | _ -> []
  in go [] e

(* ── Rule: Runtime eval/metaprogramming ───────────────────────────── *)

let eval_calls = ["parseExpr"; "parseStmt"; "macros.eval"; "eval"]

let detect_eval_usage (apps : (string * int) list) : (int * string) list =
  List.filter_map (fun (n, line) ->
    if List.exists (fun c -> n = c || String.ends_with ~suffix:("." ^ c) n) eval_calls
    then Some (line, n) else None) apps

(* ── Main analysis ────────────────────────────────────────────────── *)

let analyze_module (m : t) : finding list =
  let findings = ref [] in
  let add ~line ~rule_id ~severity ~message ?suggestion () =
    findings := { file = m.mod_path; line; rule_id; severity; message; suggestion } :: !findings
  in

  (* Process each item *)
  List.iter (fun (item : item) ->
    let loc = item.item_location in

    match item.item_value with
    | IFunction (name, params, _, body) ->
      let apps = collect_apps body in

      (* Rule: bare except *)
      List.iter (fun (line, msg) ->
        add ~line ~rule_id:"nim-bare-except" ~severity:Warning ~message:msg ()
      ) (detect_bare_except body);

      (* Rule: empty rescue (except body only discard) *)
      List.iter (fun line ->
        add ~line ~rule_id:"nim-empty-rescue" ~severity:Warning
          ~message:"except branch body is only `discard` — errors are silently swallowed"
          ~suggestion:"Handle the exception or at least log it" ()
      ) (detect_empty_rescue body);

      (* Rule: unused parameters *)
      (if not (is_test_file m.mod_path) then
        List.iter (fun p ->
          add ~line:loc.start.line ~rule_id:"nim-unused-param" ~severity:Hint
            ~message:(Printf.sprintf "Parameter '%s' of '%s' is never used" p name)
            ~suggestion:"Remove it or rename to '_'" ()
        ) (detect_unused_params params body));

      (* Rule: shadowed variables *)
      List.iter (fun (line, n) ->
        add ~line ~rule_id:"nim-shadowed-var" ~severity:Hint
          ~message:(Printf.sprintf "'%s' shadows an outer binding in the same procedure" n)
          ~suggestion:"Rename the inner binding — shadowing hides the outer value" ()
      ) (detect_shadowed_vars body);

      (* Rule: debug leftovers *)
      (if not (is_test_file m.mod_path) then
        List.iter (fun line ->
          add ~line ~rule_id:"nim-debug-leftover" ~severity:Hint
            ~message:"debugEcho left in code — debug instrumentation shipped in a scan"
            ~suggestion:"Remove debugEcho or guard with when defined(debug)" ()
        ) (detect_debug_leftover apps));

      (* Rule: deprecated APIs *)
      List.iter (fun (fn_name, line) ->
        List.iter (fun (dep, repl) ->
          if fn_name = dep then
            add ~line ~rule_id:"nim-deprecated-api" ~severity:Warning
              ~message:(Printf.sprintf "'%s' is deprecated" fn_name)
              ~suggestion:("Use " ^ repl) ()
        ) deprecated_apis
      ) apps;

      (* Rule: mass assignment from parsed JSON *)
      List.iter (fun line ->
        add ~line ~rule_id:"nim-mass-assignment" ~severity:Warning
          ~message:"Parsed JSON converted wholesale via .to(Object) — untrusted fields land unfiltered"
          ~suggestion:"Extract and validate individual fields instead of .to(Object)" ()
      ) (detect_mass_assignment body);

      (* Rule: runtime eval/metaprogramming *)
      List.iter (fun (line, fn_name) ->
        add ~line ~rule_id:"nim-eval-usage" ~severity:Hint
          ~message:(Printf.sprintf "'%s' evaluates code from strings at runtime" fn_name)
          ~suggestion:"Prefer typed parsing; runtime metaprogramming on untrusted input is dangerous" ()
      ) (detect_eval_usage apps);

      (* Rule: long method *)
      let stmt_count = count_statements body in
      if stmt_count > 50 then
        add ~line:loc.start.line ~rule_id:"nim-long-method" ~severity:Warning
          ~message:(Printf.sprintf "Procedure '%s' has %d statements (threshold: 50). Consider splitting into smaller procedures." name stmt_count)
          ~suggestion:"Break into smaller, focused procedures" ()
      else if stmt_count > 30 then
        add ~line:loc.start.line ~rule_id:"nim-long-method" ~severity:Hint
          ~message:(Printf.sprintf "Procedure '%s' has %d statements (threshold: 30). Consider refactoring." name stmt_count) ();

      (* Rule: dangerous calls without checking result *)
      List.iter (fun (fn_name, line) ->
        List.iter (fun (dangerous, msg) ->
          if fn_name = dangerous || String.ends_with ~suffix:("." ^ dangerous) fn_name then
            add ~line ~rule_id:"nim-unchecked-dangerous-call" ~severity:Warning ~message:msg ()
        ) dangerous_calls
      ) apps;

      (* Rule: hallucinated functions *)
      List.iter (fun (fn_name, line) ->
        List.iter (fun (hallucinated, suggestion) ->
          if fn_name = hallucinated || String.ends_with ~suffix:("." ^ hallucinated) fn_name then
            add ~line ~rule_id:"nim-hallucinated-function" ~severity:Warning
              ~message:(Printf.sprintf "Suspicious function '%s' — likely AI hallucination" fn_name)
              ~suggestion ()
        ) hallucinated_nim
      ) apps;

      (* Rule: unsafe parser calls outside try/except *)
      List.iter (fun (line, fn_name) ->
        add ~line ~rule_id:"nim-unsafe-conversion" ~severity:Warning
          ~message:(Printf.sprintf "'%s' can raise on invalid input but is called outside a try/except block" fn_name)
          ~suggestion:"Wrap in try/except or use the two-argument form (e.g. parseInt(s, default))" ()
      ) (collect_unsafe_outside_try ~in_try:false body)

    | IConstant (_, _, value) ->
      (* Check constant initializers for dangerous calls *)
      let apps = collect_apps value in
      List.iter (fun (fn_name, line) ->
        List.iter (fun (dangerous, msg) ->
          if fn_name = dangerous || String.ends_with ~suffix:("." ^ dangerous) fn_name then
            add ~line ~rule_id:"nim-unchecked-dangerous-call" ~severity:Warning ~message:msg ()
        ) dangerous_calls
      ) apps

    | _ -> ()
  ) m.mod_items;

  List.rev !findings
