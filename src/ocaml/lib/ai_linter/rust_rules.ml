(* src/ocaml/lib/ai_linter/rust_rules.ml
Rust-specific AST rules for antipattern and AI hallucination detection.

Key areas:
1. AI hallucinated functions (Python/Ruby/Go APIs used in Rust)
2. Unsafe patterns: unwrap(), expect(), panic
3. Common mistakes: cloning, String vs &str
4. Best practices: proper error handling
5. Security: file operations, SQL, hardcoded values
*)

open Catseye_ast.Types
open Types

(* Expose stdlib functions that may be shadowed *)

(* ── Helpers ──────────────────────────────────────────────────────── *)

let is_test_or_bench (file : string) : bool =
let lower = String.lowercase_ascii file in
(* Check for common test/benchmark patterns: suffix and path markers *)
List.exists (fun pat ->
let plen = String.length pat in
String.length lower >= plen &&
let suffix = String.sub lower (String.length lower - plen) plen in
pat = suffix || (String.length lower >= 5 && String.sub lower 0 5 = "test_")
) ["_test.rs"; "_bench.rs"; "_tests.rs"; "/test/"; "/bench/"; "/tests/"]

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
) ["std::"; "core::"; "Vec::"; "String::"; "Option::"; "Result::"; "HashMap::"; ".unwrap"; ".expect"; ".ok"; ".err"]

(* ── Recursive app collector (reused by multiple rules) ─────────────── *)

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

(* ── Rule: Long Method (too many statements) ───────────────────────── *)

let detect_long_method (m : t) : finding list =
let threshold = 30 in
let rec aux (e : expr) : int =
match e.expr_value with
| EBlock es -> List.fold_left (+) 0 (List.map aux es)
| ELet (_, e1, e2) -> aux e1 + aux e2
| EIf (_, t, o) -> aux t + (match o with Some e -> aux e | None -> 0)
| ECase (_, bs) -> List.fold_left (+) 0 (List.map (fun (_, b) -> aux b) bs)
| EFn (_, b) -> aux b
| _ -> 1
in
if is_test_or_bench m.mod_path then []
else
List.concat_map (fun item ->
match item.item_value with
| IFunction (name, _, _, body) ->
let stmts = aux body in
if stmts > threshold then
[{ rule_id = "LongMethod"; severity = Warning;
file = m.mod_path; line = item.item_location.start.line;
message = Printf.sprintf "Function '%s' has %d statements (threshold: %d)" name stmts threshold;
suggestion = Some "Consider extracting helper functions or refactoring" }]
else []
| _ -> []
) m.mod_items

(* ── Rule: Magic String / Hardcoded Values ────────────────────────── *)

let is_hex_char c =
(c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')

let is_alphanum c =
(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')

let is_likely_safe_string (s : string) : bool =
let len = String.length s in
(* UUIDs: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx *)
(len = 36 && String.contains s '-' &&
String.for_all (fun c -> is_alphanum c || c = '-') s) ||
(* Base64: only alnum, +, /, = *)
(len >= 20 && String.for_all (fun c ->
is_alphanum c || c = '+' || c = '/' || c = '=' || c = '\n') s) ||
(* Hex strings: all hex digits *)
(len >= 16 && String.for_all is_hex_char s) ||
(* File paths *)
(len > 20 && (String.contains s '/' || String.contains s '\\')) ||
(* Email-like *)
String.contains s '@'

let detect_magic_strings (m : t) : finding list =
if is_test_or_bench m.mod_path then []
else
let rec collect (e : expr) : finding list =
match e.expr_value with
| ELiteral (LString s) when String.length s > 40 && not (is_likely_safe_string s) && not (String.contains s ' ') ->
(* Likely a magic string - long no-space strings that aren't in safe patterns *)
[{ rule_id = "MagicString"; severity = Hint;
file = m.mod_path; line = e.expr_location.start.line;
message = "Hardcoded string literal should be a named constant";
suggestion = Some ("Extract to a named const") }]
| EBlock es -> List.concat (List.map collect es)
| ELet (_, e1, e2) -> collect e1 @ collect e2
| EIf (_, t, o) -> collect t @ (match o with Some e -> collect e | None -> [])
| _ -> []
in
List.concat (List.map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) -> collect body
| _ -> []
) m.mod_items)

(* ── Rule: Non-atomic File Operations ─────────────────────────────── *)

let detect_non_atomic_file_ops (m : t) : finding list =

List.concat_map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) ->
List.concat_map (fun (name, line) ->
if List.mem name ["set_permissions"; "std::fs::set_permissions"; ".set_permissions"; "chmod"] then
[{ rule_id = "NonAtomicFileOp"; severity = Hint;
file = m.mod_path; line;
message = "Non-atomic file permission change - use File::create or atomic_write with permissions";
suggestion = Some "Consider using std::fs::OpenOptions with .create(true).mode() for atomic permission setting" }]
else []
) (collect_apps body)
| _ -> []
) m.mod_items

(* ── Rule: Unbounded File Read ─────────────────────────────────────── *)

let detect_unbounded_read (m : t) : finding list =
let unbounded_reads = [
"std::fs::read"; "fs::read"; "std::fs::read_to_string"; "fs::read_to_string";
"std::io::read_to_end"; "read_to_end"; "read_to_string";
] in

List.concat_map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) ->
List.concat_map (fun (call_name, line) ->
if List.exists (fun p ->
String.length call_name >= String.length p &&
String.sub call_name 0 (String.length p) = p
) unbounded_reads then
[{ rule_id = "UnboundedRead"; severity = Warning;
file = m.mod_path; line;
message = "Unbounded file read: " ^ call_name ^ " - may cause OOM for large files";
suggestion = Some "Consider reading with a size limit or using a streaming approach" }]
else []
) (collect_apps body)
| _ -> []
) m.mod_items

(* ── Rule: Hardcoded URLs ──────────────────────────────────────────── *)

let has_url_scheme (s : string) : bool =
let len = String.length s in
(* Require :// scheme separator to avoid false positives *)
(len >= 7 && String.sub s 0 7 = "http://") ||
(len >= 8 && String.sub s 0 8 = "https://") ||
(len >= 6 && String.sub s 0 6 = "ftp://") ||
(len >= 7 && String.sub s 0 7 = "sftp://")

let is_localhost (s : string) : bool =
s = "localhost" || s = "127.0.0.1" || s = "0.0.0.0"

let detect_hardcoded_urls (m : t) : finding list =
if is_test_or_bench m.mod_path then []
else
let rec collect (e : expr) : finding list =
match e.expr_value with
| ELiteral (LString s) ->
if has_url_scheme s || is_localhost s then
[{ rule_id = "HardcodedUrl"; severity = Warning;
file = m.mod_path; line = e.expr_location.start.line;
message = "Hardcoded URL should be configurable via environment or config file";
suggestion = Some "Use std::env::var(\"API_URL\") or a config module" }]
else []
| EBlock es -> List.concat (List.map collect es)
| ELet (_, e1, e2) -> collect e1 @ collect e2
| EIf (_, t, o) -> collect t @ (match o with Some e -> collect e | None -> [])
| _ -> []
in
List.concat (List.map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) -> collect body
| _ -> []
) m.mod_items)

(* ── Rule: unwrap/expect in Library Code ───────────────────────────── *)

let detect_unsafe_in_lib (m : t) : finding list =
if is_test_or_bench m.mod_path then []
else

List.concat_map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) ->
List.concat_map (fun (call_name, line) ->
if call_name = "unwrap" || call_name = "expect" || call_name = ".unwrap" || call_name = ".expect" then
[{ rule_id = "UnsafeInLib"; severity = Warning;
file = m.mod_path; line;
message = "unwrap/expect in library function may panic - library should propagate errors";
suggestion = Some "Return Result<T, E> and use ? operator" }]
else []
) (collect_apps body)
| _ -> []
) m.mod_items

(* ── Rule: Ignored Permission Operations ────────────────────────────── *)

let detect_ignored_permissions (m : t) : finding list =
let permission_calls = [
"set_permissions";
"std::fs::set_permissions";
"fs::set_permissions";
".set_permissions";
"chmod";
"std::fs::chmod";
] in

List.concat_map (fun item ->
match item.item_value with
| IFunction (_, _, _, body) ->
List.concat_map (fun (name, line) ->
if List.exists (fun p ->
String.length name >= String.length p &&
String.sub name 0 (String.length p) = p
) permission_calls then
[{ rule_id = "IgnoredPermission"; severity = Warning;
file = m.mod_path; line;
message = "Permission operation " ^ name ^ " return value should be checked";
suggestion = Some "Handle the Result<(), Error> properly instead of ignoring it" }]
else []
) (collect_apps body)
| _ -> []
) m.mod_items

(* ── Main analysis ─────────────────────────────────────────────────── *)

let analyze_module (mod_ : Catseye_ast.Types.t) : finding list =
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

(* Run all Rust-specific rules *)
List.concat [
detect_ignored_permissions mod_;
detect_unsafe_in_lib mod_;
detect_unbounded_read mod_;
detect_non_atomic_file_ops mod_;
detect_hardcoded_urls mod_;
detect_magic_strings mod_;
detect_long_method mod_;
walk_items mod_.mod_items;
]