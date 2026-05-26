(* src/ocaml/lib/ai_linter/javascript_rules.ml
   JavaScript/TypeScript AST rules for antipattern and AI hallucination detection.
   
   Categories:
   1. AI hallucinated methods (Python/Ruby/Java APIs used in JS)
   2. Security antipatterns (eval, prototype pollution, incomplete sanitization)
   3. Best practice violations (debugger, alert, leftover debugging)
   4. Code quality (loose equality, promise chain hell, deprecated APIs)
 *)

open Base
module List = Stdlib.List
module String = Stdlib.String
module Hashtbl = Stdlib.Hashtbl
module Printf = Stdlib.Printf

(* String comparison operators *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

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
  | ETuple es -> List.concat_map collect_app_names es
  | EList es -> List.concat_map collect_app_names es
  | EFn (_, body) -> collect_app_names body
  | EFieldAccess (recv, _) -> collect_app_names recv
  | _ -> []

let rec collect_binops (e : expr) : (string * int) list =
  match e.expr_value with
  | EBinOp (_, op, _) -> [(op, e.expr_location.start.line)]
  | EApp (_, args) -> List.concat_map collect_binops args
  | EBlock es -> List.concat_map collect_binops es
  | ELet (_, e1, e2) -> collect_binops e1 @ collect_binops e2
  | EIf (cond, then_, else_) ->
    collect_binops cond @ collect_binops then_ @
    (match else_ with Some e2 -> collect_binops e2 | None -> [])
  | EFn (_, body) -> collect_binops body
  | ETuple es -> List.concat_map collect_binops es
  | _ -> []

let rec collect_var_names (e : expr) : (string * int) list =
  match e.expr_value with
  | EVar name -> [(name, e.expr_location.start.line)]
  | EApp (fn, args) -> collect_var_names fn @ List.concat_map collect_var_names args
  | EBlock es -> List.concat_map collect_var_names es
  | ELet (_, e1, e2) -> collect_var_names e1 @ collect_var_names e2
  | EIf (cond, then_, else_) ->
    collect_var_names cond @ collect_var_names then_ @
    (match else_ with Some e2 -> collect_var_names e2 | None -> [])
  | EFn (_, body) -> collect_var_names body
  | _ -> []

let rec walk_items_for_apps (items : item list) : (string * int) list =
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_app_names body
    | IConstant (_, _, body) -> collect_app_names body
    | IModule (_, subs) -> walk_items_for_apps subs
    | _ -> []
  ) items

let rec walk_items_for_binops (items : item list) : (string * int) list =
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_binops body
    | IConstant (_, _, body) -> collect_binops body
    | IModule (_, subs) -> walk_items_for_binops subs
    | _ -> []
  ) items

let rec walk_items_for_vars (items : item list) : (string * int) list =
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> collect_var_names body
    | IConstant (_, _, body) -> collect_var_names body
    | IModule (_, subs) -> walk_items_for_vars subs
    | _ -> []
  ) items

(* ── 1. AI Hallucinated Methods ─────────────────────────────────────── *)

type method_entry = {
  name : string;
  correct : string;
  category : string;
}

let hallucinated_methods : (string * method_entry) list = [
  (* Python *)
  ("strip",        { name = "strip";        correct = "Use .trim()";                category = "Ghost Scent" });
  ("len",          { name = "len";          correct = "Use .length (property)";      category = "Ghost Scent" });
  ("append",       { name = "append";       correct = "Use .push()";                 category = "Ghost Scent" });
  ("extend",       { name = "extend";       correct = "Use .push(...arr) or concat()"; category = "Ghost Scent" });
  ("remove",       { name = "remove";       correct = "Use .filter() or .splice()";  category = "Ghost Scent" });
  ("dict",         { name = "dict";         correct = "Use {} or new Map()";          category = "Ghost Scent" });
  ("print",        { name = "print";        correct = "Use console.log()";            category = "Ghost Scent" });
  ("range",        { name = "range";        correct = "Use Array.from({length:n},(_,i)=>i)"; category = "Ghost Scent" });
  ("enumerate",    { name = "enumerate";    correct = "Use arr.entries() or forEach((val,i)=>...)"; category = "Ghost Scent" });
  ("isinstance",   { name = "isinstance";   correct = "Use typeof or instanceof";     category = "Ghost Scent" });
  ("format",       { name = "format";       correct = "Use template literals `${var}`"; category = "Ghost Scent" });
  ("startswith",   { name = "startswith";   correct = "Use .startsWith() (camelCase)"; category = "Ghost Scent" });
  ("endswith",     { name = "endswith";     correct = "Use .endsWith() (camelCase)";  category = "Ghost Scent" });
  ("lower",        { name = "lower";        correct = "Use .toLowerCase()";           category = "Ghost Scent" });
  ("upper",        { name = "upper";        correct = "Use .toUpperCase()";           category = "Ghost Scent" });
  ("join",         { name = "join";         correct = "JS: arr.join(sep), not sep.join(arr)"; category = "Happy Path" });
  (* Ruby *)
  ("puts",         { name = "puts";         correct = "Use console.log()";            category = "Ghost Scent" });
  ("nil",          { name = "nil";          correct = "Use null or undefined";        category = "Ghost Scent" });
  ("select",       { name = "select";       correct = "Use .filter() (not .select())"; category = "Ghost Scent" });
  ("reject",       { name = "reject";       correct = "Use .filter(x => !cond)";      category = "Ghost Scent" });
  ("collect",      { name = "collect";      correct = "Use .map()";                   category = "Ghost Scent" });
  ("inject",       { name = "inject";       correct = "Use .reduce()";                category = "Ghost Scent" });
  ("compact",      { name = "compact";      correct = "Use .filter(Boolean)";         category = "Ghost Scent" });
  (* Java *)
  ("System.out.println", { name = "System.out.println"; correct = "Use console.log()";   category = "Ghost Scent" });
  ("Integer.parseInt",   { name = "Integer.parseInt";   correct = "Use parseInt(str, 10)"; category = "Ghost Scent" });
  (* PHP *)
  ("array_push",   { name = "array_push";   correct = "Use arr.push()";               category = "Ghost Scent" });
  ("strlen",       { name = "strlen";       correct = "Use .length property";          category = "Ghost Scent" });
  ("strpos",       { name = "strpos";       correct = "Use .indexOf()";                category = "Ghost Scent" });
  ("substr",       { name = "substr";       correct = "Use .substring() or .slice()";  category = "Ghost Scent" });
  ("implode",      { name = "implode";      correct = "Use arr.join(sep)";             category = "Ghost Scent" });
  ("explode",      { name = "explode";      correct = "Use str.split(sep)";            category = "Ghost Scent" });
  ("var_dump",     { name = "var_dump";     correct = "Use console.log() or console.dir()"; category = "Ghost Scent" });
  ("echo",         { name = "echo";         correct = "Use console.log()";             category = "Ghost Scent" });
]

let hallucinated_method_map : (string, method_entry) Hashtbl.t =
  let tbl = Hashtbl.create 64 in
  List.iter (fun (_, e) -> Hashtbl.add tbl e.name e) hallucinated_methods;
  tbl

(* ── 2. Security Antipatterns ──────────────────────────────────────── *)

(** eval, Function constructor, implicit eval via setTimeout/setInterval with string *)
let check_dangerous_exec (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "eval" | "window.eval" ->
      Some { T.file = path; line; rule_id = "eval-usage";
        severity = T.Error;
        message = "eval() executes arbitrary code — never use with user input";
        suggestion = Some "Use JSON.parse() for data, or a sandboxed evaluator" }
    | "Function" ->
      Some { T.file = path; line; rule_id = "eval-usage";
        severity = T.Error;
        message = "new Function() is equivalent to eval() — avoid dynamic code generation";
        suggestion = Some "Use static functions or JSON.parse() for data" }
    | "setTimeout" | "setInterval" ->
      Some { T.file = path; line; rule_id = "implicit-eval";
        severity = T.Warning;
        message = Printf.sprintf "%s() with a string argument acts like eval()" name;
        suggestion = Some "Pass a function reference instead of a string" }
    | "child_process.exec" | "child_process.execSync" ->
      Some { T.file = path; line; rule_id = "command-injection";
        severity = T.Error;
        message = "child_process.exec() with dynamic input is a command injection risk";
        suggestion = Some "Use execFile() with explicit args array" }
    | _ -> None
  ) all_apps

(** Hardcoded secrets *)
let is_secret_var (name : string) : bool =
  let lower = String.lowercase_ascii name in
  let starts_with prefix str =
    let plen = String.length prefix in
    String.length str >= plen && String.sub str 0 plen = prefix
  in
  List.exists (starts_with lower) [
    "password"; "secret"; "api_key"; "apikey"; "token"; "access_token";
    "private_key"; "auth_token"; "refresh_token"; "client_secret";
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
            suggestion = Some "Use environment variables or a secrets manager" }]
       | _ -> [])
    | IModule (_, subs) -> check_hardcoded_secrets subs path
    | _ -> []
  ) items

(** Incomplete string sanitization: str.replace("char", ...) only replaces first occurrence *)
let check_incomplete_sanitization (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    (* We can't fully check arg types from AST, but flag .replace with single-char string patterns *)
    if name = "replace" then
      Some { T.file = path; line; rule_id = "incomplete-sanitization";
        severity = T.Hint;
        message = ".replace() with a string argument only replaces the first occurrence";
        suggestion = Some "Use .replaceAll() or .replace(/pattern/g, ...) for global replacement" }
    else None
  ) all_apps

(** Object.assign with JSON.parse — mass assignment / prototype pollution *)
let check_object_assign (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "Object.assign" ->
      Some { T.file = path; line; rule_id = "mass-assignment";
        severity = T.Warning;
        message = "Object.assign with untrusted data can lead to mass assignment or prototype pollution";
        suggestion = Some "Validate/spread only known keys, use Object.create(null)" }
    | _ -> None
  ) all_apps

(** Dangerous __proto__, constructor, prototype access *)
let check_proto_pollution (all_vars : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "__proto__" | "__defineGetter__" | "__defineSetter__" | "__lookupGetter__" | "__lookupSetter__" ->
      Some { T.file = path; line; rule_id = "prototype-pollution";
        severity = T.Error;
        message = Printf.sprintf "Access to '%s' is a prototype pollution risk" name;
        suggestion = Some "Use Object.create(null) or Map for safe key-value storage" }
    | _ -> None
  ) all_vars

(* ── 3. Best Practice Violations ────────────────────────────────────── *)

(** Leftover debugging: alert, debugger, confirm, prompt *)
let check_debugging (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "alert" ->
      Some { T.file = path; line; rule_id = "leftover-debugging";
        severity = T.Warning;
        message = "alert() should not be in production code";
        suggestion = Some "Remove or replace with proper UI notification" }
    | "debugger" ->
      Some { T.file = path; line; rule_id = "leftover-debugging";
        severity = T.Warning;
        message = "debugger statement left in code";
        suggestion = Some "Remove debugger statement before deploying" }
    | "confirm" ->
      Some { T.file = path; line; rule_id = "leftover-debugging";
        severity = T.Hint;
        message = "confirm() is a blocking browser dialog — avoid in production";
        suggestion = Some "Use a custom modal dialog instead" }
    | "prompt" ->
      Some { T.file = path; line; rule_id = "leftover-debugging";
        severity = T.Hint;
        message = "prompt() is a blocking browser dialog — avoid in production";
        suggestion = Some "Use a form input or custom dialog instead" }
    | "console.log" | "console.debug" ->
      Some { T.file = path; line; rule_id = "leftover-debugging";
        severity = T.Hint;
        message = "console.log/debug left in code";
        suggestion = Some "Remove or replace with proper logging library" }
    | _ -> None
  ) all_apps

(* ── 4. Code Quality ───────────────────────────────────────────────── *)

(** Loose equality == and != *)
let check_loose_equality (all_binops : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (op, line) ->
    match op with
    | "==" ->
      Some { T.file = path; line; rule_id = "loose-equality";
        severity = T.Hint;
        message = "Use === instead of == to avoid type coercion bugs";
        suggestion = Some "Always use === and !== for strict equality" }
    | "!=" ->
      Some { T.file = path; line; rule_id = "loose-equality";
        severity = T.Hint;
        message = "Use !== instead of != to avoid type coercion bugs";
        suggestion = Some "Always use === and !== for strict equality" }
    | _ -> None
  ) all_binops

(** Useless self-comparison: x == x (always true) *)
let check_useless_comparison (_all_binops : (string * int) list) (_path : string) : T.finding list =
  (* We can't see both sides from binop list, skip for now *)
  []

(** Deprecated APIs *)
let check_deprecated (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "document.write" | "document.writeln" ->
      Some { T.file = path; line; rule_id = "deprecated-api";
        severity = T.Warning;
        message = Printf.sprintf "%s() is deprecated and causes performance issues" name;
        suggestion = Some "Use DOM manipulation (textContent, createElement)" }
    | "XMLHttpRequest" ->
      Some { T.file = path; line; rule_id = "deprecated-api";
        severity = T.Hint;
        message = "XMLHttpRequest is outdated";
        suggestion = Some "Use fetch() for modern async HTTP" }
    | "escape" | "unescape" ->
      Some { T.file = path; line; rule_id = "deprecated-api";
        severity = T.Warning;
        message = Printf.sprintf "%s() is deprecated — use encodeURIComponent/decodeURIComponent" name;
        suggestion = Some "Use encodeURIComponent() / decodeURIComponent()" }
    | _ -> None
  ) all_apps

(** Deep .then() chains (promise pyramid of doom) *)
let rec check_promise_chains (items : item list) (path : string) : T.finding list =
  let rec count_then_depth (e : expr) : int =
    match e.expr_value with
    | EApp (fn, _) ->
      (match fn.expr_value with
       | EFieldAccess (recv, "then") | EFieldAccess (recv, "catch") -> 1 + count_then_depth recv
       | _ -> 0)
    | _ -> 0
  in
  let rec find_deep_chains (e : expr) : T.finding list =
    let depth = count_then_depth e in
    let self = if depth >= 4 then
      [{ T.file = path; line = e.expr_location.start.line;
         rule_id = "promise-chain-hell"; severity = T.Hint;
         message = Printf.sprintf "Deep .then() chain (%d levels) — consider async/await" depth;
         suggestion = Some "Refactor to async/await for readability" }]
    else [] in
    let children = match e.expr_value with
      | EApp (_, args) -> List.concat_map find_deep_chains args
      | EBlock es -> List.concat_map find_deep_chains es
      | ELet (_, e1, e2) -> find_deep_chains e1 @ find_deep_chains e2
      | EIf (_, then_, else_) ->
        find_deep_chains then_ @ (match else_ with Some e2 -> find_deep_chains e2 | None -> [])
      | _ -> []
    in
    self @ children
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> find_deep_chains body
    | IConstant (_, _, body) -> find_deep_chains body
    | IModule (_, subs) -> check_promise_chains subs path
    | _ -> []
  ) items

(** Math.random() / pseudoRandomBytes for security-sensitive contexts *)
let check_weak_random (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "Math.random" ->
      Some { T.file = path; line; rule_id = "weak-random";
        severity = T.Warning;
        message = "Math.random() is not cryptographically secure";
        suggestion = Some "Use crypto.getRandomValues() or crypto.randomBytes() for security" }
    | _ -> None
  ) all_apps

(* ── 5. Callback Hell (deep callback nesting) ──────────────────────── *)

(** Count nesting depth of callback patterns:
    EApp where an arg is an EFn (anonymous callback).
    3+ levels is callback hell. *)
let rec count_callback_depth (e : expr) : int =
  match e.expr_value with
  | EApp (_, args) ->
    let has_callback = List.exists (fun a ->
      match a.expr_value with EFn _ -> true | _ -> false
    ) args in
    if has_callback then
      let inner_max = List.fold_left (fun acc a ->
        match a.expr_value with
        | EFn (_, body) -> max acc (count_callback_depth body)
        | _ -> acc
      ) 0 args in
      1 + inner_max
    else 0
  | _ -> 0

let rec find_callback_hell (e : expr) : (int * int) list =
  let depth = count_callback_depth e in
  let self = if depth >= 3 then
    [(depth, e.expr_location.start.line)]
  else [] in
  let children = match e.expr_value with
    | EApp (_, args) -> List.concat_map find_callback_hell args
    | EBlock es -> List.concat_map find_callback_hell es
    | ELet (_, e1, e2) -> find_callback_hell e1 @ find_callback_hell e2
    | EIf (_, then_, else_) ->
      find_callback_hell then_ @ (match else_ with Some e2 -> find_callback_hell e2 | None -> [])
    | _ -> []
  in
  self @ children

let check_callback_hell (items : item list) (path : string) : T.finding list =
  let rec walk (items : item list) : T.finding list =
    List.concat_map (fun (item : item) ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.map (fun (depth, line) ->
          { T.file = path; line; rule_id = "callback-hell";
            severity = T.Warning;
            message = Printf.sprintf "Callback nesting %d levels deep — use async/await or Promises" depth;
            suggestion = Some "Refactor to async/await for readability" }
        ) (find_callback_hell body)
      | IModule (_, subs) -> walk subs
      | _ -> []
    ) items
  in
  walk items

(* ── 6. Assignment in condition ──────────────────────────────────────── *)

(** Detect `if (x = expr)` which is likely a typo for `==`/`===`.
    We look for EIf where the condition is an EAssignment. *)
let rec find_assignment_in_condition (e : expr) : int list =
  match e.expr_value with
  | EIf (cond, _, _) ->
    let self = match cond.expr_value with
      | EAssignment _ -> [cond.expr_location.start.line]
      | _ -> []
    in
    self @ find_assignment_in_condition cond
  | EBlock es -> List.concat_map find_assignment_in_condition es
  | ELet (_, e1, e2) -> find_assignment_in_condition e1 @ find_assignment_in_condition e2
  | EApp (fn, args) ->
    find_assignment_in_condition fn @ List.concat_map find_assignment_in_condition args
  | _ -> []

let check_assignment_in_condition (items : item list) (path : string) : T.finding list =
  let rec walk (items : item list) : T.finding list =
    List.concat_map (fun (item : item) ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.map (fun line ->
          { T.file = path; line; rule_id = "assignment-in-condition";
            severity = T.Error;
            message = "Assignment in if condition — likely meant == or === comparison";
            suggestion = Some "Use === for strict equality comparison" }
        ) (find_assignment_in_condition body)
      | IModule (_, subs) -> walk subs
      | _ -> []
    ) items
  in
  walk items

(* ── 7. Nested ternary ──────────────────────────────────────────────── *)

(** Detect ternary expressions nested inside other ternaries.
    In the AST, a ternary `a ? b : c` maps to EIf.
    Nested EIf inside EIf branches = nested ternary. *)
let rec count_ternary_depth (e : expr) : int =
  match e.expr_value with
  | EIf (_, then_, else_) ->
    let then_d = count_ternary_depth then_ in
    let else_d = match else_ with Some e -> count_ternary_depth e | None -> 0 in
    1 + max then_d else_d
  | _ -> 0

let rec find_nested_ternary (e : expr) : (int * int) list =
  match e.expr_value with
  | EIf (_, then_, else_) ->
    let depth = count_ternary_depth e in
    let self = if depth >= 2 then
      [(depth, e.expr_location.start.line)]
    else [] in
    self
    @ find_nested_ternary then_
    @ (match else_ with Some e2 -> find_nested_ternary e2 | None -> [])
  | EBlock es -> List.concat_map find_nested_ternary es
  | ELet (_, e1, e2) -> find_nested_ternary e1 @ find_nested_ternary e2
  | EApp (fn, args) ->
    find_nested_ternary fn @ List.concat_map find_nested_ternary args
  | _ -> []

let check_nested_ternary (items : item list) (path : string) : T.finding list =
  let rec walk (items : item list) : T.finding list =
    List.concat_map (fun (item : item) ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.map (fun (depth, line) ->
          { T.file = path; line; rule_id = "nested-ternary";
            severity = T.Warning;
            message = Printf.sprintf "Nested ternary %d levels deep — use if/else or a lookup table" depth;
            suggestion = Some "Replace nested ternary with if/else statements or a lookup map" }
        ) (find_nested_ternary body)
      | IModule (_, subs) -> walk subs
      | _ -> []
    ) items
  in
  walk items

(* ── 8. Async function without await ────────────────────────────────── *)

(** Detect async functions that don't use await.
    Heuristic: function name starts with "async" in the source, or the
    function body has no `await` calls. Since our AST doesn't have an
    async flag, we look for functions that call `.then()` chains
    (should use await instead) or have a body that never references `await`.
    Actually: detect functions whose body contains EApp(EVar "await", _)
    — no, that's sync functions in async context.
    Instead: detect .then() chains (already covered) and functions
    returning Promises without await. For now, flag any function that
    has EApp with fn being EFieldAccess(_, "then") without any await in the body. *)

let rec has_await (e : expr) : bool =
  match e.expr_value with
  | EApp (fn, _) ->
    (match fn.expr_value with
     | EVar "await" -> true
     | _ -> has_await fn)
    || (match e.expr_value with EApp (_, args) -> List.exists has_await args | _ -> false)
  | EBlock es -> List.exists has_await es
  | ELet (_, e1, e2) -> has_await e1 || has_await e2
  | EIf (_, then_, else_) ->
    has_await then_ || (match else_ with Some e -> has_await e | None -> false)
  | EFn (_, body) -> has_await body
  | _ -> false

let rec has_then_chain (e : expr) : bool =
  match e.expr_value with
  | EApp (fn, _) ->
    (match fn.expr_value with
     | EFieldAccess (_, "then") -> true
     | _ -> has_then_chain fn)
    || (match e.expr_value with EApp (_, args) -> List.exists has_then_chain args | _ -> false)
  | EBlock es -> List.exists has_then_chain es
  | ELet (_, e1, e2) -> has_then_chain e1 || has_then_chain e2
  | EIf (_, then_, else_) ->
    has_then_chain then_ || (match else_ with Some e -> has_then_chain e | None -> false)
  | _ -> false

let check_promise_not_awaited (items : item list) (path : string) : T.finding list =
  let rec walk (items : item list) : T.finding list =
    List.concat_map (fun (item : item) ->
      match item.item_value with
      | IFunction (name, _, _, body) when has_then_chain body && not (has_await body) ->
        [{ T.file = path; line = item.item_location.start.line;
           rule_id = "promise-not-awaited";
           severity = T.Hint;
           message = Printf.sprintf "Function '%s' uses .then() chains without await — consider using async/await" name;
           suggestion = Some "Convert to async function and use await instead of .then() chains" }]
      | IModule (_, subs) -> walk subs
      | _ -> []
    ) items
  in
  walk items

(* ── 9. Insecure cookie / Hardcoded IP / Console assert ────────────── *)

(** Hardcoded IP addresses — placeholder for future implementation.
    Currently handled by Crystal rules for all languages. *)
let _check_hardcoded_ip (_all_apps : (string * int) list) (_path : string) : T.finding list = []

(** Detect console.assert left in production code. *)
let check_console_assert (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "console.assert" ->
      Some { T.file = path; line; rule_id = "leftover-debugging";
        severity = T.Hint;
        message = "console.assert() should not be in production code — use a proper assertion library";
        suggestion = Some "Replace with a proper test or assertion library" }
    | _ -> None
  ) all_apps

(* ── 10. Error message leakage ──────────────────────────────────────── *)

(** Detect patterns where internal error details are sent to the client.
    Flag: res.send(err), res.json(err), res.json({ error: err.message })
    Heuristic: look for send/json/set calls with err/error/e as argument. *)
let rec find_error_leakage (e : expr) : (string * int) list =
  match e.expr_value with
  | EApp (fn, args) ->
    let fn_name = expr_name fn in
    let is_sender = fn_name = "res.send" || fn_name = "res.json"
                   || fn_name = "response.send" || fn_name = "response.json"
                   || fn_name = "ctx.body" in
    let has_error_arg = List.exists (fun a ->
      match a.expr_value with
      | EVar v -> v = "err" || v = "error" || v = "e"
      | EFieldAccess (inner, field) ->
        (match inner.expr_value with
         | EVar v -> (v = "err" || v = "error") && (field = "message" || field = "stack")
         | _ -> false)
      | _ -> false
    ) args in
    let self = if is_sender && has_error_arg then
      [(fn_name, e.expr_location.start.line)]
    else [] in
    self @ find_error_leakage fn @ List.concat_map find_error_leakage args
  | EBlock es -> List.concat_map find_error_leakage es
  | ELet (_, e1, e2) -> find_error_leakage e1 @ find_error_leakage e2
  | EIf (_, then_, else_) ->
    find_error_leakage then_ @ (match else_ with Some e -> find_error_leakage e | None -> [])
  | EFn (_, body) -> find_error_leakage body
  | _ -> []

let check_error_leakage (items : item list) (path : string) : T.finding list =
  let rec walk (items : item list) : T.finding list =
    List.concat_map (fun (item : item) ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.map (fun (fn, line) ->
          { T.file = path; line; rule_id = "error-leakage";
            severity = T.Warning;
            message = Printf.sprintf "%s with error object — leaking internal details to client" fn;
            suggestion = Some "Send a generic error message, log the details server-side" }
        ) (find_error_leakage body)
      | IModule (_, subs) -> walk subs
      | _ -> []
    ) items
  in
  walk items

(* ── 11. Unbounded file operations (Node.js) ──────────────────────── *)

(** Detect unbounded read operations that could cause OOM with large files.
    Functions like fs.readFileSync/readFile load entire file into memory.
    NOTE: fs.promises.readFile is async and won't cause OOM for large files. *)
let unbounded_read_patterns = [
  "fs.readFileSync"; "fs.readFile";
  "readFileSync"; "readFile";
]

let is_unbounded_read name =
  List.exists (fun p ->
    String.length name >= String.length p &&
    String.sub name (String.length name - String.length p) (String.length p) = p
  ) unbounded_read_patterns

let check_unbounded_read (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    if is_unbounded_read name then
      Some { T.file = path; line; rule_id = "unbounded-file-read";
        severity = T.Warning;
        message = Printf.sprintf "Unbounded read: %s — loads entire file into memory, OOM risk for large files"
          (if String.length name > 30 then String.sub name 0 30 ^ "..." else name);
        suggestion = Some "Use streaming (fs.createReadStream) or read with size limits" }
    else None
  ) all_apps

(* ── 12. TOCTOU pattern ──────────────────────────────────────────── *)

(** Detect check-then-act patterns that could be race conditions (TOCTOU).
    Common patterns: fs.exists + fs.readFile, fs.access + fs.readFile, etc.
    NOTE: fs.exists() is deprecated - prefer fs.access() with error handling. *)
let check_pattern = [
  (* Deprecated but still common *)
  ("exists", "readFile"); ("existsSync", "readFileSync");
  ("exists", "open"); ("existsSync", "openSync");
  ("exists", "writeFile"); ("existsSync", "writeFileSync");
  (* Modern fs.access patterns *)
  ("access", "readFile"); ("accessSync", "readFileSync");
  ("access", "open"); ("accessSync", "openSync");
  ("access", "writeFile"); ("accessSync", "writeFileSync");
  (* fs.stat/lstat check patterns *)
  ("stat", "readFile"); ("statSync", "readFileSync");
  ("stat", "open"); ("statSync", "openSync");
  ("lstat", "readFile"); ("lstatSync", "readFileSync");
  (* Qualified names *)
  ("fs.exists", "fs.readFile"); ("fs.existsSync", "fs.readFileSync");
  ("fs.access", "fs.readFile"); ("fs.accessSync", "fs.readFileSync");
  ("fs.stat", "fs.readFile"); ("fs.statSync", "fs.readFileSync");
]

let find_check_then_act (e : expr) : (int * string * string) list =
  let results = ref [] in
  let rec aux (e : expr) =
    match e.expr_value with
    | EIf (cond, then_, else_) ->
      (match cond.expr_value with
       | EApp (fn, _) ->
         let fn_name = expr_name fn in
         (match List.assoc_opt fn_name check_pattern with
          | Some action ->
            let check_line = cond.expr_location.start.line in
            let rec find_action_exprs (ex : expr) =
              match ex.expr_value with
              | EApp (fn2, _) ->
                let fn2_name = expr_name fn2 in
                if fn2_name = action then
                  results := (check_line, fn_name, fn2_name) :: !results
                else find_action_exprs fn2
              | EBlock es -> List.iter find_action_exprs es
              | _ -> ()
            in
            (match then_.expr_value with EBlock es -> List.iter find_action_exprs es | _ -> find_action_exprs then_)
          | None -> ())
       | _ -> ());
       aux cond; aux then_; (match else_ with Some e2 -> aux e2 | None -> ())
    | EBlock es -> List.iter aux es
    | ELet (_, e1, e2) -> aux e1; aux e2
    | EFn (_, body) -> aux body
    | _ -> ()
  in
  aux e;
  !results

let check_toctou (items : item list) (path : string) : T.finding list =
  let rec walk (items : item list) : T.finding list =
    List.concat_map (fun (item : item) ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.map (fun (check_line, check_fn, action_fn) ->
          { T.file = path; line = check_line; rule_id = "toctou-pattern";
            severity = T.Warning;
            message = Printf.sprintf "TOCTOU: %s check followed by %s action — race condition possible"
              check_fn action_fn;
            suggestion = Some "Perform operation atomically or use try/catch around the action" }
        ) (find_check_then_act body)
      | IModule (_, subs) -> walk subs
      | _ -> []
    ) items
  in
  walk items


let analyze_module (mod_ : Catseye_ast.Types.t) : T.finding list =
  let all_apps = walk_items_for_apps mod_.mod_items in
  let all_binops = walk_items_for_binops mod_.mod_items in
  let all_vars = walk_items_for_vars mod_.mod_items in
  let path = mod_.mod_path in

  (* Hallucinated methods *)
  let hallucination_findings = List.filter_map (fun (name, line) ->
    let last = try let i = String.rindex name '.' in String.sub name (i+1) (String.length name - i - 1) with Stdlib.Not_found -> name in
    match (Hashtbl.find_opt hallucinated_method_map name, Hashtbl.find_opt hallucinated_method_map last) with
    | Some entry, _ | _, Some entry ->
      Some { T.file = path; line; rule_id = "hallucinated-method";
        severity = T.Warning;
        message = Printf.sprintf "'%s' doesn't exist in JS/TS — %s" name entry.correct;
        suggestion = Some entry.correct }
    | None, None -> None
  ) all_apps in

  let security = check_dangerous_exec all_apps path
    @ check_hardcoded_secrets mod_.mod_items path
    @ check_incomplete_sanitization all_apps path
    @ check_object_assign all_apps path
    @ check_proto_pollution all_vars path
    @ check_weak_random all_apps path
  in

  let best_practice = check_debugging all_apps path in

  let quality = check_loose_equality all_binops path
    @ check_deprecated all_apps path
    @ check_promise_chains mod_.mod_items path
  in

  let file_ops = check_unbounded_read all_apps path @ check_toctou mod_.mod_items path in

  hallucination_findings @ security @ best_practice @ quality @ file_ops
  @ check_callback_hell mod_.mod_items path
  @ check_assignment_in_condition mod_.mod_items path
  @ check_nested_ternary mod_.mod_items path
  @ check_promise_not_awaited mod_.mod_items path
  @ check_console_assert all_apps path
  @ check_error_leakage mod_.mod_items path
