(* src/ocaml/lib/ai_linter/crystal_rules.ml
   Crystal-specific AST rules

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
 *)

open Base
module List = Stdlib.List
module String = Stdlib.String
module Hashtbl = Stdlib.Hashtbl
module Printf = Stdlib.Printf
module Map = Stdlib.Map
module Float = Stdlib.Float
module Int = Stdlib.Int
module Char = Stdlib.Char

(* String comparison operators *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

open Catseye_ast.Types

module T = Types

let list_sort_uniq cmp l =
  let sorted = Stdlib.List.sort (fun a b -> cmp a b) l in
  let rec dedup acc = function
    | [] -> List.rev acc
    | [x] -> List.rev (x :: acc)
    | x :: (y :: _ as rest) when cmp x y = 0 -> dedup acc (y :: rest)
    | x :: rest -> dedup (x :: acc) rest
  in
  dedup [] sorted

(* ── File path helpers ──────────────────────────────────────────────── *)

(** Check if a file path is a test/benchmark/spec file that should be exempt
    from certain AI antipattern checks. Test files often intentionally use
    simplified patterns, debug output, or have many parameters for test data. *)
let is_test_or_spec_file (file : string) : bool =
  let lower = String.lowercase_ascii file in
  let rec contains_substr str pat =
    let plen = String.length pat in
    let slen = String.length str in
    if plen > slen then false
    else if String.sub str 0 plen = pat then true
    else contains_substr (String.sub str 1 (slen - 1)) pat
  in
  let matched = List.exists (fun pat ->
    let plen = String.length pat in
    if String.length lower >= plen then
      let suffix = String.sub lower (String.length lower - plen) plen in
      pat = suffix || (pat = "test_" && String.length lower >= 5 && String.sub lower 0 5 = "test_")
      || contains_substr lower pat
    else false
  ) [
    "/test/"; "/spec/"; "/benchmark/"; "/bench/";
    "/example/"; "/examples/"; "/tests/";
    "_test.cr"; "_spec.cr"; "_bench.cr";
    "_test."; "_spec."; "_bench.";
    "_tests.cr"; "test_"; "spec_";
    "smell_";  (* smell sample test files *)
  ] in
  matched

(* ── Expression helpers ─────────────────────────────────────────────── *)

(** Get the full dotted name string from an expression *)
let rec get_name_chain (e : expr) : string list =
  match e.expr_value with
  | EFieldAccess (recv, field) -> get_name_chain recv @ [field]
  | EVar name -> [name]
  | _ -> []

let get_full_name (e : expr) : string =
  String.concat "." (get_name_chain e)

(** Collect all function calls (EApp) from an expression tree *)
let rec collect_app_names (e : expr) : (string * int) list =
  match e.expr_value with
  | EApp (fn, args) ->
      let name = get_full_name fn in
      (name, e.expr_location.start.line) :: List.concat_map collect_app_names args
  | EBlock es -> List.concat_map collect_app_names es
  | ELet (_, e1, e2) -> collect_app_names e1 @ collect_app_names e2
  | EIf (cond, then_, else_) ->
      collect_app_names cond @ collect_app_names then_ @
      (match else_ with Some e -> collect_app_names e | None -> [])
  | ECase (scrut, branches) ->
      collect_app_names scrut @ List.concat (List.map (fun (_, e) -> collect_app_names e) branches)
  | EFieldAccess (recv, _) -> collect_app_names recv
  | ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body; _ } ->
      (* Also traverse rescue clauses and ensure block *)
      let rescue_calls = List.concat_map (fun rc -> collect_app_names rc.rescue_body) rescue_clauses in
      let ensure_calls = match ensure_body with Some e -> collect_app_names e | None -> [] in
      let else_calls = match else_body with Some e -> collect_app_names e | None -> [] in
      collect_app_names try_body @ rescue_calls @ ensure_calls @ else_calls
  | _ -> []

(* ── Hallucinated Method Database ──────────────────────────────────── *)

type method_entry = {
  name : string;
  correct : string;
  category : string;
  lang : [ `Crystal | `Ruby | `JS | `Elixir ];
}

(** Methods that don't exist in Crystal, often suggested by AI.
    Each entry: the hallucinated name, the correct Crystal alternative,
    the source language AI is confusing it with, and a category. *)
let hallucinated_methods : method_entry list = [
  (* Ruby methods that don't exist in Crystal *)
  { name = "to_map"; correct = "to_h or .map { |k, v| ... }";
    category = "Ghost Scent"; lang = `Ruby };
  { name = "Array.compact"; correct = "Array.reject(&.nil?)";
    category = "Ghost Scent"; lang = `Ruby };
  { name = "String.to_sym"; correct = "Crystal has symbols natively — use :symbol";
    category = "Ghost Scent"; lang = `Ruby };
  { name = "Time.now"; correct = "Time.local or Time.utc";
    category = "Ghost Scent"; lang = `Ruby };
  { name = "Logger.info"; correct = "Crystal uses Log (require \"log\"), not Logger";
    category = "Ghost Scent"; lang = `Ruby };
  { name = "Array.pluck"; correct = "Array.map(&.field) — no pluck method in Crystal";
    category = "Ghost Scent"; lang = `JS };
  { name = "nil.to_s"; correct = "Use safe navigation: object&.to_s";
    category = "Happy Path"; lang = `Ruby };
  { name = "String.join"; correct = "Array.join(separator) — join is on Array, not String";
    category = "Ghost Scent"; lang = `Ruby };
  { name = "Enumerable.group_by"; correct = "Enumerable.group_by exists but returns Array({K, Array(V)})";
    category = "Ghost Scent"; lang = `Ruby };
  { name = "require \"active_record\""; correct = "Crystal uses Jennifer, Granite, or Crecto for ORM";
    category = "Mixing Ecosystems"; lang = `Ruby };
  { name = "require \"rails\""; correct = "Crystal has Lucky, Amber, or Athena — not Rails";
    category = "Mixing Ecosystems"; lang = `Ruby };
  { name = "require \"sinatra\""; correct = "Crystal has Kemal, Lucky, or Onyx — not Sinatra";
    category = "Mixing Ecosystems"; lang = `Ruby };
  { name = "require \"rspec\""; correct = "Crystal uses its built-in Spec module";
    category = "Mixing Ecosystems"; lang = `Ruby };
  { name = "require \"bundler\""; correct = "Crystal uses Shards (shards.yml)";
    category = "Mixing Ecosystems"; lang = `Ruby };
  { name = "require \"pry\""; correct = "Crystal uses ic (interactive crystal) for REPL";
    category = "Mixing Ecosystems"; lang = `Ruby };
  (* JSON.parse and HTTP::Client.get are valid Crystal — removed from hallucination DB
     to avoid false positives. The ignored-return detector handles misuse of these APIs. *)

  (* JavaScript/Lodash methods *)
  { name = "_.map"; correct = "Array.map { |x| ... } — no underscore.js in Crystal";
    category = "Mixing Ecosystems"; lang = `JS };
  { name = "_.filter"; correct = "Array.select { |x| ... } — use select, not filter";
    category = "Mixing Ecosystems"; lang = `JS };
  { name = "_.reduce"; correct = "Array.reduce(initial) { |acc, x| ... }";
    category = "Mixing Ecosystems"; lang = `JS };
  { name = "Array.forEach"; correct = "Array.each { |x| ... } — Crystal uses each, not forEach";
    category = "Mixing Ecosystems"; lang = `JS };
  { name = "console.log"; correct = "puts or pp for debugging output";
    category = "Mixing Ecosystems"; lang = `JS };
  { name = "typeof"; correct = "Crystal uses typeof() but it's a compile-time macro, not runtime";
    category = "Mixing Ecosystems"; lang = `JS };

  (* Elixir methods *)
  { name = "Enum.map"; correct = "Array.map or Enumerable.map — Crystal uses methods, not Enum module";
    category = "Mixing Ecosystems"; lang = `Elixir };
  { name = "Enum.filter"; correct = "Array.select or Enumerable.select";
    category = "Mixing Ecosystems"; lang = `Elixir };
  { name = "Enum.reduce"; correct = "Array.reduce or Enumerable.reduce";
    category = "Mixing Ecosystems"; lang = `Elixir };

  (* Deprecated Crystal patterns *)
  (* NOTE: puts, p, pp are VALID Crystal methods defined in the prelude.
     They are NOT hallucinations - they DO exist in Crystal stdlib.
     The deprecated-syntax detector catches their use separately.
     Do NOT add them to hallucinated_methods. *)

  (* Crystal-specific patterns *)
  { name = "Pointer.malloc"; correct = "Use Slice or Array for safe memory management";
    category = "Happy Path"; lang = `Crystal };
  { name = "Pointer.null"; correct = "Use Option(T) or Nil instead of null pointers";
    category = "Happy Path"; lang = `Crystal };
  { name = "unsafe_fetch"; correct = "Use Array#[] with bounds checking unless perf-critical";
    category = "Happy Path"; lang = `Crystal };
  { name = "as"; correct = "Use .as(Type) for casts — bare 'as' is not Crystal syntax";
    category = "Ghost Scent"; lang = `Crystal };
]

(** Build a lookup table from the method database.
    Key: the hallucinated method name (lowercase for case-insensitive match) *)
let method_db : (string, method_entry) Hashtbl.t =
  let tbl = Hashtbl.create 64 in
  let () = List.iter (fun entry ->
    (* Store both exact and last-component matches *)
    Hashtbl.replace tbl (String.lowercase_ascii entry.name) entry;
    (* For dotted names like "String.join", also store "join" *)
    (match String.index_opt entry.name '.' with
     | Some idx ->
         let suffix = String.sub entry.name (idx + 1) (String.length entry.name - idx - 1) in
         Hashtbl.replace tbl (String.lowercase_ascii suffix) entry
     | None -> ())
  ) hallucinated_methods in
  tbl

(** Check a call name against the hallucinated method database *)
let check_hallucinated (name : string) : method_entry option =
  Hashtbl.find_opt method_db (String.lowercase_ascii name)

(* ── Category 1: Ghost Scent ────────────────────────────────────────── *)

(** Rule 1.1: Hallucinated Standard Library Methods (database-driven) *)
let detect_hallucinated_stdlib (m : t) =
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.iter (fun (name, line) ->
        match check_hallucinated name with
        | Some entry ->
          let source_lang = match entry.lang with
            | `Ruby -> "Ruby" | `JS -> "JavaScript" | `Elixir -> "Elixir" | `Crystal -> "Crystal"
          in
          let msg = Printf.sprintf "%s does not exist in Crystal stdlib — %s (confused with %s)"
              entry.name entry.correct source_lang
          in
          collected := (msg, line) :: !collected
        | None -> ()
      ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  list_sort_uniq (fun (m1, l1) (m2, l2) ->
    let c = compare l1 l2 in if c <> 0 then c else String.compare m1 m2
  ) !collected

(** Rule 1.2: Legacy/Deprecated Syntax *)
let detect_deprecated_syntax (m : t) =
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if name = "puts" then [("puts used for debugging", line)]
        else if name = "p" then [("p used for debugging", line)]
        else if name = "pp" then [("pp used for debugging", line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(* ── Category 2: The Foreigner ──────────────────────────────────────── *)

(** Rule 2.1: Manual Loops vs Iterators
    Detect while loops with counter variable and index access patterns
    that could be replaced with .each, .map, .select, etc. *)
let detect_manual_loop (m : t) =
  
  
  
  let has_suffix s suffix =
    let sslen = String.length s in
    let slen = String.length suffix in
    sslen >= slen && String.sub s (sslen - slen) slen = suffix
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let calls = collect_app_names body in
      let has_while = List.exists (fun (n, _) -> n = "while") calls in
      let has_counter = List.exists (fun (n, _) ->
        has_suffix n "+= 1" || has_suffix n "+=1" ||
        n = "i += 1" || n = "idx += 1" || n = "index += 1") calls in
      if has_while && has_counter then
        [let line = match List.find_opt (fun (n, _) -> n = "while") calls with
          | Some (_, l) -> l | None -> item.item_location.start.line
        in ("Manual while loop with counter — consider using .each, .map, or .each_with_index", line)]
      else []
    | _ -> []
  ) m.mod_items

(** Rule 2.3: Primitive Obsession (3+ params) *)
let detect_primitive_obsession (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
      let params = List.filter (function PVar _ -> true | _ -> false) patterns in
      if List.length params >= 3
      then Some (Printf.sprintf "Function '%s' has %d parameters - consider domain types" name (List.length params), item.item_location.start.line)
      else None
    | _ -> None
  ) m.mod_items

(* ── Category 3: The Happy Path ──────────────────────────────────────── *)

(** Rule 3.1: Nil-chaser (unchecked nil access)
    Uses type inference DB to detect when a call that returns T | Nil
    is accessed without a nil guard (e.g. user.name where user comes
    from Hash#[]? or Array#first?). Also detects .not_nil!, .as(Type)
    casts, and .try(&.x) as code smells. *)
let detect_nil_chaser (m : t) =
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        let findings = [] in
        (* Pattern 1: .not_nil! — forced unwrap *)
        let findings = if name = "not_nil!" then
          ("not_nil! will raise on nil — use pattern matching or nil check instead", line) :: findings
        else findings in
        (* Pattern 2: .as( — type cast that crashes on nil *)
        let findings = if String.length name >= 3 &&
          String.sub name (String.length name - 3) 3 = ".as" then
          ("Type cast with .as() may crash if nil — consider case expression", line) :: findings
        else findings in
        (* Pattern 3: Nullable-returning call accessed without guard *)
        let findings = (match Type_inference.lookup_crystal name with
          | Some ({ kind = Nullable; doc; _ } as info) ->
            (Printf.sprintf "Call %s returns %s (%s) — access may raise on nil"
              name info.Type_inference.type_name doc, line) :: findings
          | _ -> findings) in
        (* Pattern 4: Raising accessor used without rescue *)
        let findings = (match Type_inference.lookup_crystal name with
          | Some { kind = Safe; type_name = "T"; _ } when
              String.length name >= 2 &&
              String.sub name (String.length name - 2) 2 = "[]" ->
            (Printf.sprintf "%s raises on missing key/index — use []? variant or nil check" name, line) :: findings
          | _ -> findings) in
        findings
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(** Rule 3.2: Ignoring Return Value
    Detects when a call that returns an important value (HTTP response,
    JSON parse result, DB query) has its return value discarded (no let binding).
    AI often writes `HTTP::Client.get(url)` without capturing the response. *)
let detect_ignored_return (m : t) =
  let important_returns = [
    (* HTTP/DB - errors should be handled *)
    "HTTP::Client.get"; "HTTP::Client.post"; "HTTP::Client.put";
    "HTTP::Client.delete"; "HTTP::Client.patch";
    "HTTP.get"; "HTTP.post"; "HTTP.put";
    "JSON.parse"; "JSON.parse_io";
    "DB.query"; "DB.query_one"; "DB.query_one?";
    "DB.exec";
    (* File I/O - errors should be handled *)
    "File.read"; "File.write";
    "File.read?"; "File.write?";
    (* Permission operations - failures should not be silent *)
    "chmod"; "chown"; "chgrp";
    "File.chmod"; "File.chown"; "File.chgrp";
  ] in
  
  let is_important (name : string) =
    List.exists (fun prefix ->
      String.length name >= String.length prefix &&
      String.sub name 0 (String.length prefix) = prefix
    ) important_returns
  in
  let rec check_items (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_, _, _, body) ->
        List.concat_map (fun (name, line) ->
          if is_important name then
            [Printf.sprintf "Return value of %s is discarded — capture and check the result" name, line]
          else []
        ) (collect_app_names body)
      | IModule (_, items) | IClass (_, items) ->
        check_items items
      | _ -> []
    ) items
  in
  check_items m.mod_items

let detect_unsafe_pointers (m : t) =
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if name = "Pointer.malloc" then
          [("Pointer.malloc is unsafe — use Slice or Array for safe memory management", line)]
        else if name = "Pointer.null" then
          [("Pointer.null is unsafe — use Nil or Option(T) for absent values", line)]
        else if name = "Pointer.new" then
          [("Pointer.new is unsafe — consider Slice or a safe wrapper", line)]
        else if String.length name >= 6 && String.sub name 0 6 = "unsafe" then
          [(Printf.sprintf "%s bypasses safety checks — use safe alternative if available" name, line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(** Rule: Sleep in production code *)
let detect_sleep_in_prod (m : t) =
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if name = "sleep" then [("sleep() in production code — remove or gate behind debug flag", line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(* ── Category 4: The Tangle ─────────────────────────────────────────── *)

(** Rule 4.1: Redundant Conversions
    String.new removed — valid Crystal for Bytes/Slice(UInt8) -> String conversion.
    Kept as placeholder for future redundant conversion patterns. *)
let detect_redundant_conversion (_m : t) =
  []

(* ── Category 5: The Mute Trap (Security) ───────────────────────────── *)

(* ── Category 5: The Mute Trap (Security) ───────────────────────────── *)

(** Rule 5.1: Hardcoded Secrets *)
let detect_hardcoded_secrets (m : t) =
  let pem_marker = String.make 5 '-' ^ "BEGIN RSA PRIVATE KEY" ^ String.make 5 '-' in
  let secret_prefixes = [
    "sk_"; "sk_live_"; "sk_test_";
    "ghp_"; "gho_"; "ghu_"; "ghs_";
    "AKIA"; "ASIA";
    "AIza";
    "xoxb-"; "xoxp-"; "xoxa-";
    "eyJ";
    pem_marker;
  ] in
  
  let is_likely_secret (s : string) =
    String.length s >= 20 &&
    List.exists (fun prefix ->
      String.length prefix <= String.length s &&
      String.sub s 0 (String.length prefix) = prefix
    ) secret_prefixes
  in
  let rec collect_string_literals (e : expr) : (string * int) list =
    match e.expr_value with
    | ELiteral (LString s) when is_likely_secret s ->
      [(s, e.expr_location.start.line)]
    | ELiteral _ -> []
    | EApp (fn, args) ->
      collect_string_literals fn @ List.concat_map collect_string_literals args
    | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
      collect_string_literals e1 @ collect_string_literals e2
    | EIf (_, then_, else_) ->
      collect_string_literals then_ @
      (match else_ with Some e -> collect_string_literals e | None -> [])
    | EBlock es -> List.concat_map collect_string_literals es
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      List.concat_map (fun (s, line) ->
        let masked = String.sub s 0 (min 8 (String.length s)) ^ "..." in
        [Printf.sprintf "Potential hardcoded secret in '%s': %s — use environment variables or config" name masked, line]
      ) (collect_string_literals body)
    | _ -> []
  ) m.mod_items

(* ── Category 6: The Copier (Copy-Paste) ────────────────────────────── *)

(** Rule 6.3: Hardcoded URLs/IPs *)
let detect_hardcoded_urls (m : t) =
  let is_urlish (s : string) =
    String.length s >= 8 &&
    (String.sub s 0 7 = "http://" || String.sub s 0 8 = "https://") &&
    not (s = "http://" || s = "https://" || s = "http://www." || s = "https://www.")
  in
  let is_loopback_or_meta (s : string) =
    s = "0.0.0.0" || s = "127.0.0.1" || s = "255.255.255.255" || s = "0.0.0.1"
  in
  let is_ipish (s : string) =
    let parts = String.split_on_char '.' s in
    List.length parts = 4 &&
    List.for_all (fun p -> try let _ = Stdlib.int_of_string p in true with _ -> false) parts &&
    not (is_loopback_or_meta s)
  in
  let rec collect_suspicious_strings (e : expr) : (string * int) list =
    match e.expr_value with
    | ELiteral (LString s) when is_urlish s || is_ipish s ->
      [(s, e.expr_location.start.line)]
    | ELiteral _ -> []
    | EApp (fn, args) ->
      collect_suspicious_strings fn @ List.concat_map collect_suspicious_strings args
    | ELet (_, e1, e2) | ELetAssert (_, e1, e2) ->
      collect_suspicious_strings e1 @ collect_suspicious_strings e2
    | EBlock es -> List.concat_map collect_suspicious_strings es
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := List.concat_map (fun (s, line) ->
        [Printf.sprintf "Hardcoded URL/IP: %s — use config or environment variable" s, line]
      ) (collect_suspicious_strings body) @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 7: The Confused (Language Feature Misuse) ─────────────── *)

(** Rule 7.1: Blanket Rescue
    Detects bare `rescue` or `rescue ex` without specifying an exception type.
    AI often generates blanket rescues that swallow all errors silently. *)
let detect_blanket_rescue (m : t) =
  List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let bodies = List.concat_map (fun (name, line) ->
        if name = "rescue" || name = "begin" then
          [("Blanket rescue catches all exceptions — catch specific exception types instead", line)]
        else []
      ) (collect_app_names body) in
      (match bodies with [] -> None | _ -> Some bodies)
    | _ -> None
  ) m.mod_items |> List.concat

(** Rule 7.2: Duplicate Validation
    Detects the same variable being validated twice in the same function.
    
    NOTE: Disabled for Crystal - multi-layer validation is intentional defense-in-depth,
    not duplicate code. Each validation catches different attack vectors.
*)
let detect_duplicate_validation (m : t) =
  (* Disabled for Crystal - defense-in-depth validation is intentional *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  
  let rec check_item (item : item) =
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let calls = collect_app_names body in
      let validation_methods = ["empty?"; "nil?"; "blank?"; "valid?"; "present?"; "includes?"] in
      List.iter (fun method_name ->
        let matching = List.filter (fun (n, _) ->
          String.length n >= String.length method_name &&
          String.sub n (String.length n - String.length method_name) (String.length method_name) = method_name
        ) calls in
        if List.length matching >= 3 then
          let line = match matching with (_, l) :: _ -> l | [] -> 0 in
          findings := (Printf.sprintf "%s called %d times — check for duplicate validation logic"
            method_name (List.length matching), line) :: !findings
      ) validation_methods
    | _ -> ()
  and findings = ref [] in
  List.iter check_item m.mod_items;
  !findings

(* ── Category 8: The Looper (Iteration Mistakes) ────────────────────── *)

(** Rule: Magic String Comparison
    Detects hardcoded string literals used in equality comparisons.
    AI often uses stringly-typed checks instead of enums or constants.
    Skips strings < 3 chars (like "", " ", "0") and common safe patterns. *)
let detect_magic_string (m : t) =
  let is_magic (s : string) =
    String.length s >= 3 &&
    not (String.length s >= 4 && String.sub s 0 4 = "http") &&
    not (String.length s >= 6 && String.sub s 0 6 = "sqlite") &&
    not (String.length s >= 10 && String.sub s 0 10 = "postgresql")
  in
  let rec collect_equality_strings (e : expr) : (string * int) list =
    match e.expr_value with
    | EApp (fn, args) when get_full_name fn = "==" ->
      List.filter_map (fun a ->
        match a.expr_value with
        | ELiteral (LString s) when is_magic s -> Some (s, a.expr_location.start.line)
        | _ -> None
      ) args
    | EBlock es -> List.concat_map collect_equality_strings es
    | ELet (_, e1, e2) -> collect_equality_strings e1 @ collect_equality_strings e2
    | EIf (_, then_, else_) ->
      collect_equality_strings then_ @
      (match else_ with Some e -> collect_equality_strings e | None -> [])
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := List.concat_map (fun (s, line) ->
        [Printf.sprintf "Magic string \"%s\" used in comparison — consider using a constant or enum" s, line]
      ) (collect_equality_strings body) @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Debug Require
    Detects require statements for debug/development gems that shouldn't
    be in production code. *)
let detect_debug_require (m : t) =
  let debug_requires = [
    "debug"; "pry"; "byebug"; "binding_of_caller"; "irb";
    "debugger"; "pry-byebug"; "pry-doc"; "pry-stack_explorer";
  ] in
  
  List.concat_map (fun item ->
    match item.item_value with
    | IImport (name, _) ->
      if List.mem name debug_requires then
        [let line = item.item_location.start.line in
         (Printf.sprintf "require \"%s\" is a debug dependency — remove for production" name, line)]
      else []
    | _ -> []
  ) m.mod_items

(* ── Category 9: Code Quality ────────────────────────────────────────── *)

(** Rule: Empty Catch Block
    Detects rescue/except blocks with empty bodies — errors swallowed silently.
    AI often generates empty rescue blocks as placeholders. *)
let detect_empty_catch (m : t) =
  
  let rec has_empty_rescue (e : expr) =
    match e.expr_value with
    | EApp (fn, args) when get_full_name fn = "rescue" ->
        let has_body = List.exists (fun a ->
          match a.expr_value with
          | EBlock [] | EUnit -> false
          | _ -> true
        ) args in
        if not has_body then Some e.expr_location.start.line else None
    | EBlock es -> List.find_map has_empty_rescue es
    | ELet (_, e1, e2) ->
        (match has_empty_rescue e1 with Some l -> Some l | None -> has_empty_rescue e2)
    | EIf (_, then_, else_) ->
        (match has_empty_rescue then_ with
         | Some l -> Some l
         | None -> (match else_ with Some e -> has_empty_rescue e | None -> None))
    | _ -> None
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      (match has_empty_rescue body with
       | Some line -> [("Empty rescue block — errors are silently swallowed. Log or handle the exception.", line)]
       | None -> [])
    | _ -> []
  ) m.mod_items

(* Rule: Flag Argument
    Detects boolean-style parameters (is_X, should_X, has_X, with_X, no_X).
    AI-generated code often uses flag arguments instead of separate methods or enums. *)
let detect_flag_argument (m : t) =
  
  let is_flag_name (s : string) =
    String.length s >= 3 &&
    let prefixes = ["is_"; "should_"; "has_"; "with_"; "no_"; "use_"; "enable_"; "disable_"] in
    List.exists (fun p -> String.length s > String.length p && String.sub s 0 (String.length p) = p) prefixes
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
      let flag_params = List.filter_map (function
        | PVar v when is_flag_name v -> Some v
        | _ -> None
      ) patterns in
      List.concat_map (fun p ->
        [let line = item.item_location.start.line in
         (Printf.sprintf "Function '%s' has flag argument '%s' — consider splitting into separate methods or using an enum" name p, line)]
      ) flag_params
    | _ -> []
  ) m.mod_items

(** Rule: Long Method
    Detects functions with too many expression nodes in their body.
    AI often generates monolithic functions that should be decomposed. *)
let detect_long_method (m : t) =
  let max_nodes = 50 in
  let rec count_nodes (e : expr) : int =
    match e.expr_value with
    | EBlock es -> List.fold_left (fun acc e -> acc + count_nodes e) 0 es
    | ELet (_, e1, e2) -> 1 + count_nodes e1 + count_nodes e2
    | EIf (_, then_, else_) ->
        1 + count_nodes then_ +
        (match else_ with Some e -> count_nodes e | None -> 0)
    | ECase (_, branches) ->
        1 + List.fold_left (fun acc (_, e) -> acc + count_nodes e) 0 branches
    | EApp (fn, args) -> 1 + count_nodes fn + List.fold_left (fun acc e -> acc + count_nodes e) 0 args
    | ETryCatchFinally { try_body; rescue_clauses; ensure_body; else_body; _ } ->
        1 + count_nodes try_body +
        List.fold_left (fun acc rc -> acc + count_nodes rc.rescue_body) 0 rescue_clauses +
        (match ensure_body with Some e -> count_nodes e | None -> 0) +
        (match else_body with Some e -> count_nodes e | None -> 0)
    | _ -> 1
  in
  
  let rec count_nodes (e : expr) : int =
    match e.expr_value with
    | EBlock es -> List.fold_left (fun acc e -> acc + count_nodes e) 0 es
    | EApp (_, args) -> 1 + List.fold_left (fun acc a -> acc + count_nodes a) 0 args
    | EIf (_, then_, else_) ->
      1 + count_nodes then_ +
      (match else_ with Some e -> count_nodes e | None -> 0)
    | ELet (_, e1, e2) -> 1 + count_nodes e1 + count_nodes e2
    | ECase (_, branches) ->
      1 + List.fold_left (fun acc (_, body) -> acc + count_nodes body) 0 branches
    | _ -> 1
  in
  let max_nodes = 80 in
  let rec collect_functions (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (name, _, _, body) ->
        let count = count_nodes body in
        if count > max_nodes then
          [let line = item.item_location.start.line in
           (Printf.sprintf "Function '%s' has %d AST nodes (max %d) — consider breaking into smaller functions" name count max_nodes, line)]
        else []
      | IModule (_, items) | IClass (_, items) ->
        collect_functions items
      | _ -> []
    ) items
  in
  collect_functions m.mod_items

(* ── Category 10: The Looper & Misc ─────────────────────────────────── *)

(** Rule: Infinite Recursion
    Detects a function that calls itself with the same argument names
    unchanged — a common AI mistake when generating recursive functions. *)
let detect_infinite_recursion (m : t) =
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (fname, params, _, body) ->
      let param_names = List.filter_map (function PVar v -> Some v | _ -> None) params in
      let calls = collect_app_names body in
      List.iter (fun (name, line) ->
        if name = fname then begin
          let is_unchanged = List.exists (fun p ->
            List.exists (fun (n, _) -> n = p) calls
          ) param_names in
          if is_unchanged then
            collected := (Printf.sprintf
              "Function '%s' calls itself with unchanged argument — possible infinite recursion" fname, line) :: !collected
        end
      ) calls
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Debug Print
    Broader than deprecated-syntax — catches print, printf, p!, pp!,
    stderr.puts, STDERR.print that are left in production code. *)
let detect_debug_print (m : t) =
  let debug_calls = [
    "print"; "printf"; "p!"; "pp!";
    "stderr.puts"; "STDERR.puts"; "STDERR.print"; "STDERR.printf";
    "debug_print"; "debug_puts"; "log.debug";
  ] in
  let is_debug (name : string) =
    List.exists (fun prefix ->
      name = prefix ||
      (String.length name > String.length prefix + 1 &&
       String.sub name (String.length name - String.length prefix - 1) (String.length prefix + 1) = "." ^ prefix)
    ) debug_calls
  in
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.concat_map (fun (name, line) ->
        if is_debug name then
          [(Printf.sprintf "Debug output via %s — remove or gate behind a debug flag before production" name, line)]
        else []
      ) (collect_app_names body)
    | _ -> []
  ) m.mod_items

(** Rule: String Interpolation in Query
    Detects string interpolation or concatenation patterns that build
    SQL/HTML/shell commands — a classic injection vector.
    Catches calls named like concat/interpolate near DB/query methods. *)
let detect_string_interpolation_in_query (m : t) =
  let query_methods = [
    "DB.query"; "DB.exec"; "DB.query_one"; "DB.query_one?";
    "database.query"; "db.query"; "repo.query"; "repo.exec";
  ] in
  
  let is_query (name : string) =
    List.exists (fun q ->
      String.length name >= String.length q &&
      String.sub name (String.length name - String.length q) (String.length q) = q
    ) query_methods
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let calls = collect_app_names body in
      let has_interpolation = List.exists (fun (n, _) ->
        n = "String.interpolation" || n = "String.concat" || n = "sprintf"
      ) calls in
      let has_query = List.exists (fun (n, _) -> is_query n) calls in
      if has_interpolation && has_query then
        [let line = match List.find_opt (fun (n, _) -> is_query n) calls with
          | Some (_, l) -> l | None -> 0
        in ("String interpolation used near database query — use parameterized queries instead", line)]
      else []
    | _ -> []
  ) m.mod_items

(* ── Category 11: Structural Complexity ────────────────────────────── *)

(** Rule: Complex Conditional
    Detects boolean expressions with 4+ && / || operators.
    AI often generates monster conditions instead of extracting predicates. *)
let detect_complex_conditional (m : t) =
  let max_operators = 3 in
  let rec count_bool_ops (e : expr) : int =
    match e.expr_value with
    | EApp (fn, args) ->
        let name = get_full_name fn in
        let own = if name = "&&" || name = "||" || name = "and" || name = "or" then 1 else 0 in
        own + List.fold_left (fun acc a -> acc + count_bool_ops a) 0 args
    | EBlock es -> List.fold_left (fun acc e -> acc + count_bool_ops e) 0 es
    | ELet (_, e1, e2) -> count_bool_ops e1 + count_bool_ops e2
    | EIf (_, then_, else_) ->
        count_bool_ops then_ + (match else_ with Some e -> count_bool_ops e | None -> 0)
    | _ -> 0
  in
  
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let count = count_bool_ops body in
      if count > max_operators then
        [let line = item.item_location.start.line in
         (Printf.sprintf "Function '%s' has %d boolean operators (max %d) — extract into named predicates" name count max_operators, line)]
      else []
    | _ -> []
  ) m.mod_items

(** Rule: Message Chain (Law of Demeter)
    Detects call chains with 5+ dotted segments like `a.b.c.d.e.f`.
    AI often generates deep chains instead of using intermediate variables. *)
let detect_message_chain (m : t) =
  let max_depth = 4 in
  let rec chain_depth (e : expr) : int =
    match e.expr_value with
    | EFieldAccess (recv, _) -> 1 + chain_depth recv
    | _ -> 0
  in
  let rec find_chains (e : expr) : (int * int) list =
    match e.expr_value with
    | EApp (fn, args) ->
        let depth = chain_depth fn in
        let hits = if depth > max_depth then [(depth, e.expr_location.start.line)] else [] in
        hits @ List.concat_map find_chains args
    | EBlock es -> List.concat_map find_chains es
    | ELet (_, e1, e2) -> find_chains e1 @ find_chains e2
    | EIf (_, then_, else_) ->
        find_chains then_ @ (match else_ with Some e -> find_chains e | None -> [])
    | _ -> []
  in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.iter (fun (depth, line) ->
        collected := (Printf.sprintf
          "Call chain has %d segments (max %d) — violates Law of Demeter, use intermediate variables"
          depth max_depth, line) :: !collected
      ) (find_chains body)
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Nested Ternary
    Detects nested ternary expressions (? :). AI sometimes generates
    deeply nested ternaries instead of case/cond. *)
let detect_nested_ternary (m : t) =
  let rec count_ternary_depth (e : expr) : int =
    match e.expr_value with
    | EIf (_, then_, else_) ->
        let then_depth = count_ternary_depth then_ in
        let else_depth = match else_ with Some e -> count_ternary_depth e | None -> 0 in
        1 + max then_depth else_depth
    | EBlock es -> List.fold_left (fun acc e -> max acc (count_ternary_depth e)) 0 es
    | ELet (_, e1, e2) -> max (count_ternary_depth e1) (count_ternary_depth e2)
    | _ -> 0
  in
  let rec find_nested_ternaries (e : expr) : int list =
    match e.expr_value with
    | EIf (_, then_, else_) when count_ternary_depth e >= 3 ->
        (* This is a nested ternary of depth 3+ *)
        e.expr_location.start.line :: List.concat_map find_nested_ternaries (
          then_ :: (match else_ with Some e -> [e] | None -> []))
    | EBlock es -> List.concat_map find_nested_ternaries es
    | ELet (_, e1, e2) -> find_nested_ternaries e1 @ find_nested_ternaries e2
    | _ -> []
  in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      List.iter (fun line ->
        collected := ("Nested ternary expression (3+ levels) — use case/cond for readability", line) :: !collected
      ) (find_nested_ternaries body)
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 12: Design Smells ──────────────────────────────────────── *)

(** Rule: Data Clump
    Detects the same pair of parameters appearing together in 3+ functions.
    AI often generates repetitive parameter lists instead of grouping into a record. *)
let detect_data_clump (m : t) =
  let min_co_occurrence = 3 in
  (* Collect all function parameter sets *)
  let param_sets = List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, params, _, _) ->
        Some (List.filter_map (function PVar v -> Some v | _ -> None) params)
    | _ -> None
  ) m.mod_items in
  (* Count how many functions each parameter appears in *)
  let param_counts = Hashtbl.create 32 in
  List.iter (fun params ->
    List.iter (fun p ->
      let current = try Hashtbl.find param_counts p with Stdlib.Not_found -> 0 in
      Hashtbl.replace param_counts p (current + 1)
    ) params
  ) param_sets;
  (* Find pairs that co-occur in 3+ functions *)
  let pair_counts = Hashtbl.create 64 in
  List.iter (fun params ->
    let sorted = list_sort_uniq String.compare params in
    let rec count_pairs = function
      | [] | [_] -> ()
      | a :: rest ->
          List.iter (fun b ->
            let key = a ^ "," ^ b in
            let current = try Hashtbl.find pair_counts key with Stdlib.Not_found -> 0 in
            Hashtbl.replace pair_counts key (current + 1)
          ) rest;
          count_pairs rest
    in
    count_pairs sorted
  ) param_sets;

(** Rule: Data Clump
    Detects the same pair of parameters appearing together in 3+ functions.
    AI often generates repetitive parameter lists instead of grouping into a record. *)
let detect_data_clump (m : t) =
  let min_co_occurrence = 3 in
  
  
  
  
  let param_sets = List.filter_map (fun item ->
    match item.item_value with
    | IFunction (_, params, _, _) ->
      Some (List.filter_map (function PVar v -> Some v | _ -> None) params)
    | _ -> None
  ) m.mod_items in
  let pair_counts = Hashtbl.create 64 in
  List.iter (fun params ->
    let sorted = list_sort_uniq String.compare params in
    let rec count_pairs = function
      | [] | [_] -> ()
      | a :: rest ->
        List.iter (fun b ->
          let key = a ^ "," ^ b in
          let current = try Hashtbl.find pair_counts key with Stdlib.Not_found -> 0 in
          Hashtbl.replace pair_counts key (current + 1)
        ) rest;
        count_pairs rest
    in
    count_pairs sorted
  ) param_sets in
  let collected = List.concat_map (fun (key, count) ->
    if count >= min_co_occurrence then
      let pair_name = String.map (fun c -> if c = ',' then ' ' else c) key in
      let line = List.hd m.mod_items |> fun i -> i.item_location.start.line in
      [Printf.sprintf "Parameters %s appear together in %d functions — consider grouping into a record" pair_name count, line]
    else []
  ) (Hashtbl.fold (fun key count acc -> (key, count) :: acc) pair_counts []) in
  list_sort_uniq (fun (_, l1) (_, l2) -> compare l1 l2) collected

(** Rule: Feature Envy
    Detects functions that make most of their calls on a single external type.
    AI often generates functions that should be methods on the envied object. *)
let detect_feature_envy (m : t) =
  let min_calls = 5 in
  let envy_threshold = 0.7 in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let calls = collect_app_names body in
      (* Count calls by receiver prefix *)
      let receiver_counts = Hashtbl.create 16 in
      List.iter (fun (call_name, _) ->
        (match String.index_opt call_name '.' with
         | Some idx ->
             let receiver = String.sub call_name 0 idx in
             let current = try Hashtbl.find receiver_counts receiver with Stdlib.Not_found -> 0 in
             Hashtbl.replace receiver_counts receiver (current + 1)
         | None -> ());
      ) calls;
      let total_calls = List.length calls in
      if total_calls >= min_calls then
        Hashtbl.iter (fun receiver count ->
          let ratio = Float.of_int count /. Float.of_int total_calls in
          if ratio >= envy_threshold then
            collected := (Printf.sprintf
              "Function '%s' makes %d/%d calls on '%s' (%.0f%%) — consider moving to %s module"
              name count total_calls receiver (ratio *. 100.0) receiver,
              item.item_location.start.line) :: !collected
        ) receiver_counts
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 13: Dead Code ────────────────────────────────────────── *)

(** Rule: Dead Code After Error
    Detects code that appears after a raise/error expression.
    
    NOTE: In Crystal, guard clauses are idiomatic:
    ```crystal
    def validate!(x)
      raise Error.new if invalid?  # raise is the ERROR path
      # This IS reachable - it's the NORMAL path
    end
    ```
    This rule is DISABLED for Crystal as it produces false positives on guard patterns.
*)
let detect_dead_code_after_error (m : t) =
  (* Disabled for Crystal - guard clauses produce false positives *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  
  let rec scan_block (exprs : expr list) : (string * int) list =
    match exprs with
    | [] | [_] -> []
    | e :: rest ->
      let results = (match e.expr_value with
       | EError _ ->
         List.concat_map (fun dead ->
           [Printf.sprintf "Unreachable code after raise/error on line %d" e.expr_location.start.line,
            dead.expr_location.start.line]
         ) rest
       | EIf (_, then_, else_) ->
         let then_results = (match then_.expr_value with EError _ ->
           List.concat_map (fun dead ->
             [Printf.sprintf "Unreachable code after raise in conditional on line %d"
               then_.expr_location.start.line, dead.expr_location.start.line]
           ) rest
         | _ -> []) in
         let else_results = (match else_ with
          | Some e2 -> (match e2.expr_value with
            | EError _ ->
              List.concat_map (fun dead ->
                [Printf.sprintf "Unreachable code after raise in conditional on line %d"
                  e2.expr_location.start.line, dead.expr_location.start.line]
              ) rest
            | _ -> [])
          | None -> []) in
         then_results @ else_results
       | _ -> []) in
      results @ scan_block rest
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      (match body.expr_value with
       | EBlock exprs -> scan_block exprs
       | _ -> [])
    | _ -> []
  ) m.mod_items

(* ── Category 14: Async & DRY ───────────────────────────────────────── *)

(** Rule: Non-Atomic File Operation
    Detects patterns like File.write followed by chmod on the same path.
    This is a non-atomic operation that creates a race window.
    Suggest using File.atomic_write or setting permissions during creation. *)
let detect_non_atomic_file_op (m : t) =
  
  let rec check_items (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_name, _, _, body) ->
        let calls = collect_app_names body in
        let perm_calls = List.filter (fun (call_name, _) ->
          List.mem call_name ["chmod"; "chown"; "chgrp"; "File.chmod"; "File.chown"; "File.chgrp"]
        ) calls in
        List.concat_map (fun (perm_call, perm_line) ->
          [Printf.sprintf
            "Non-atomic file operation: %s should be combined with file creation or use File.atomic_write with proper permissions"
            perm_call, perm_line]
        ) perm_calls
      | IModule (_, items) | IClass (_, items) ->
        check_items items
      | _ -> []
    ) items
  in
  check_items m.mod_items

(** Rule: Unbounded File Read
    Detects unbounded file reads that could cause OOM with large files.
    File.read reads entire file into memory. *)
let detect_unbounded_file_read (m : t) =
  let unbounded_reads = [
    "File.read"; "File.read?";
    "IO.copy";
  ] in
  
  let rec check_items (items : item list) =
    List.concat_map (fun item ->
      match item.item_value with
      | IFunction (_name, _, _, body) ->
        List.concat_map (fun (call_name, line) ->
          if List.exists (fun p ->
            String.length call_name >= String.length p &&
            String.sub call_name 0 (String.length p) = p
          ) unbounded_reads then
            [let msg = Printf.sprintf "Unbounded file read: %s loads entire file into memory - OOM risk for large files" call_name in (msg, line)]
          else []
        ) (collect_app_names body)
      | IModule (_, items) | IClass (_, items) ->
        check_items items
      | _ -> []
    ) items
  in
  check_items m.mod_items

(** Rule: Callback Hell
    Detects 3+ levels of nested EFn (anonymous functions / blocks).
    AI often generates deeply nested callbacks instead of flat control flow. *)
let detect_callback_hell (m : t) =
  let max_depth = 2 in
  let rec fn_depth (e : expr) : int =
    match e.expr_value with
    | EFn (_, body) -> 1 + fn_depth body
    | EBlock es -> List.fold_left (fun acc e -> max acc (fn_depth e)) 0 es
    | ELet (_, e1, e2) -> max (fn_depth e1) (fn_depth e2)
    | EIf (_, then_, else_) ->
        max (fn_depth then_)
          (match else_ with Some e -> fn_depth e | None -> 0)
    | EApp (fn, args) -> max (fn_depth fn) (List.fold_left (fun acc a -> max acc (fn_depth a)) 0 args)
    | _ -> 0
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let depth = fn_depth body in
      if depth > max_depth then
        collected := (Printf.sprintf
          "Function '%s' has %d levels of nested closures (max %d) — flatten with named functions"
          name depth max_depth, item.item_location.start.line) :: !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Repeated Regex
    Detects the same regex literal appearing in 2+ functions.
    AI often duplicates regex patterns instead of extracting to a constant. *)
let detect_repeated_regex (m : t) =
  let module StringMap = Map.Make(String) in
  let regex_by_func = StringMap.empty in
  let regex_locations = StringMap.empty in
  
  let rec collect_regexes (e : expr) : string list =
    match e.expr_value with
    | ELiteral (LString s) when
        String.length s >= 3 &&
        (String.length s >= 2 && String.sub s 0 1 = "/" ||
         String.length s >= 3 && String.sub s 0 2 = "r/") ->
        [s]
    | ELiteral (LString s) when
        String.length s >= 4 &&
        (String.sub s 0 1 = "^" || String.sub s (String.length s - 1) 1 = "$") &&
        List.exists (fun c -> String.contains s c) ['.'; '*'; '+'; '?'; '['; '('; '|'] ->
        [s]
    | EBlock es -> List.concat_map collect_regexes es
    | ELet (_, e1, e2) -> collect_regexes e1 @ collect_regexes e2
    | EApp (fn, args) -> collect_regexes fn @ List.concat_map collect_regexes args
    | EIf (_, then_, else_) ->
        collect_regexes then_ @ (match else_ with Some e -> collect_regexes e | None -> [])
    | _ -> []
  in
  let (regex_by_func, regex_locations) =
    List.fold_left (fun (by_func, locs) item ->
      match item.item_value with
      | IFunction (name, _, _, body) ->
        let rx_list = collect_regexes body in
        let new_by_func = List.fold_left (fun acc rx ->
          let funcs = try StringMap.find rx acc with Stdlib.Not_found -> [] in
          StringMap.add rx (name :: funcs) acc
        ) by_func rx_list in
        let new_locs = List.fold_left (fun acc rx ->
          let line = item.item_location.start.line in
          let existing = try StringMap.find rx acc with Stdlib.Not_found -> [] in
          StringMap.add rx ((name, line) :: existing) acc
        ) locs rx_list in
        (new_by_func, new_locs)
      | _ -> (by_func, locs)
    ) (regex_by_func, regex_locations) m.mod_items in
  List.concat_map (fun (rx, locations) ->
    if List.length locations >= 2 then
      let funcs = String.concat ", " (List.map fst locations) in
      let _, line = List.hd locations in
      [Printf.sprintf "Regex %s duplicated in functions: %s — extract to a constant" rx funcs, line]
    else []
  ) (StringMap.bindings regex_locations)

(* ── Category 15: Arity ────────────────────────────────────────────── *)

(** Rule: Too Many Parameters
    Detects functions with 7+ parameters.
    AI often generates functions with too many arguments instead of
    grouping into a configuration record/struct. *)
let detect_too_many_params (m : t) =
  let max_params = 6 in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, params, _, _) ->
      let count = List.length params in
      if count > max_params then
        collected := (Printf.sprintf
          "Function '%s' has %d parameters (max %d) — group into a configuration record"
          name count max_params, item.item_location.start.line) :: !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 16: Exception Safety ─────────────────────────────────── *)

(** Rule: Open Rescue
    Detects rescue blocks that catch all exceptions without specifying a type.
    AI often generates bare 'rescue' or 'rescue ex' instead of 'rescue SpecificError'.
    Catches everything including SignalException, NoMemoryError etc. *)
let detect_open_rescue (m : t) =
  
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EApp (fn, args) ->
      (if get_full_name fn = "rescue" then
        [("Open rescue catches all exceptions — specify the exception type (e.g. rescue ArgumentError)", e.expr_location.start.line)]
      else []) @
      scan fn @ List.concat_map scan args
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> scan body
    | _ -> []
  ) m.mod_items

(** Rule: Missing Else
    Detects if-expressions without an else branch where the result appears
    to be used (assigned to a variable or returned as last expression).
    Missing else means nil is implicitly returned for the false branch.
    AI often forgets the else branch, causing unexpected nil values. *)
let detect_missing_else (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EIf (cond, then_, None) ->
      [("if expression without else — false branch implicitly returns nil", e.expr_location.start.line)]
      @ scan cond @ scan then_
    | EIf (cond, then_, Some else_) ->
      scan cond @ scan then_ @ scan else_
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 17: Control Flow Clarity ──────────────────────────────── *)

(** Rule: Reassignment in Condition
    Detects variable reassignment inside if/case conditions.
    AI sometimes mutates variables in conditions, leading to subtle bugs
    and hard-to-read code. *)
let detect_reassignment_in_condition (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EIf (cond, then_, else_) ->
      (match cond.expr_value with
       | EAssignment _ ->
         [("Assignment inside if condition — extract to a separate binding for clarity", cond.expr_location.start.line)]
       | _ -> []) @
      scan cond @ scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> scan e) branches
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Unreachable Code
    Detects any code after return-like statements (EError, or raise-equivalents)
    in a block.
    
    NOTE: In Crystal, guard clauses are idiomatic:
    ```crystal
    def validate!(x)
      raise Error.new if invalid?  # raise is the ERROR path
      # This IS reachable - it's the NORMAL path when not invalid
    end
    ```
    The 'unreachable' code after a guard raise is actually normal continuation.
    This rule is DISABLED for Crystal as it produces false positives on guard patterns.
*)
let detect_unreachable_code (m : t) =
  (* Disabled for Crystal - guard clauses produce false positives *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  
  let is_terminal (e : expr) =
    match e.expr_value with
    | EError _ -> true
    | EApp (fn, _) ->
        let name = get_full_name fn in
        name = "return" || name = "raise" || name = "fail" || name = "exit"
        || name = "abort"
    | _ -> false
  in
  let rec scan_block terminal_line = function
    | [] | [_] -> []
    | e :: rest when is_terminal e ->
      List.concat_map (fun dead ->
        [Printf.sprintf "Unreachable code after terminal statement on line %d"
          terminal_line, dead.expr_location.start.line]
      ) rest
    | _ :: rest -> scan_block terminal_line rest
  in
  let rec scan (e : expr) =
    match e.expr_value with
    | EBlock es ->
      let dead = (match es with
        | [] -> []
        | terminal :: _ when is_terminal terminal ->
          List.concat_map (fun dead ->
            [Printf.sprintf "Unreachable code after terminal statement on line %d"
              terminal.expr_location.start.line, dead.expr_location.start.line]
          ) (List.tl es)
        | _ -> []) in
      dead @ List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> scan e) branches
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 18: Type & Network ────────────────────────────────────── *)

(** Rule: Type Checker Abuse
    Detects 3+ is_a?/as/responds_to? calls in one function.
    AI often generates manual type checking instead of using polymorphism.
    Indicates the function should be split or use method dispatch. *)
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
let detect_unless_with_else (m : t) =
  
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EApp (fn, args) ->
      (if get_full_name fn = "unless" && List.length args >= 2 then
        [("unless with else is a double-negative — rewrite as if/else", e.expr_location.start.line)]
      else []) @
      scan fn @ List.concat_map scan args
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 20: Correctness ────────────────────────────────────────── *)

(** Rule: Global Variable
    Detects $-prefixed global variables in Crystal.
    AI trained on Ruby often uses $globals which are a code smell in Crystal.
    Use class variables, constants, or module-level state instead. *)
let detect_global_variable (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EVar v when String.length v > 1 && String.sub v 0 1 = "$" ->
      [Printf.sprintf "Global variable $%s — use a constant or module-level binding instead"
        (String.sub v 1 (String.length v - 1)), e.expr_location.start.line]
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | ECase (_, branches) -> List.concat_map (fun (_, e) -> scan e) branches
    | _ -> []
  in
  List.concat_map (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) -> scan body
    | _ -> []
  ) m.mod_items

(** Rule: Float Equality Comparison
    Detects == comparisons involving float literals or float-returning functions.
    Float equality is unreliable due to precision — use delta comparison.
    AI often generates naive float == float checks. *)
let detect_float_equality (m : t) =
  let is_float_expr (e : expr) =
    match e.expr_value with
    | ELiteral (LFloat _) -> true
    | ELiteral (LString s) ->
      String.length s > 0 &&
      let has_dot = String.contains s '.' in
      let is_num = List.for_all (fun c -> Char.code c >= 48 && Char.code c <= 57 || c = '.')
        (List.init (String.length s) (fun i -> s.[i])) in
      has_dot && is_num
    | _ -> false
  in
  let is_float_fn (name : string) =
    List.exists (fun s ->
      String.length name >= String.length s &&
      String.sub name (String.length name - String.length s) (String.length s) = s
    ) ["to_f"; ".floor"; ".ceil"; ".round"; ".abs"; "Float"; "rand"]
  in
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EBinOp (e1, op, e2) when op = "==" || op = "!=" ->
      (if is_float_expr e1 || is_float_expr e2 ||
         is_float_fn (get_full_name e1) || is_float_fn (get_full_name e2) then
        [("Float equality comparison is unreliable — use delta comparison (abs(a - b) < epsilon)",
          e.expr_location.start.line)]
      else []) @
      scan e1 @ scan e2
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 21: Idiomatic Crystal ─────────────────────────────────── *)

(** Rule: Sequential Blocking Calls
    Detects 3+ blocking calls in a function that could be parallelized.
    
    NOTE: Disabled for Crystal - validation is inherently sequential.
    File.expand_path depends on validate_path! passing.
*)
let detect_sequential_blocking (m : t) =
  (* Disabled for Crystal - validation is inherently sequential *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  let blocking_prefixes = [
    "HTTP::Client"; "DB."; "File."; "Process";
  ] in
  let is_blocking (name : string) =
    List.exists (fun prefix ->
      String.length name >= String.length prefix &&
      String.sub name 0 (String.length prefix) = prefix
    ) blocking_prefixes
  in
  let rec collect_blocking_calls (e : expr) : string list =
    match e.expr_value with
    | EApp (fn, args) ->
      let name = get_full_name fn in
      let self_calls = if is_blocking name then [name] else [] in
      self_calls @ List.concat_map collect_blocking_calls args
    | EBlock es -> List.concat_map collect_blocking_calls es
    | ELet (_, e1, e2) -> collect_blocking_calls e1 @ collect_blocking_calls e2
    | EIf (_, then_, else_) ->
      collect_blocking_calls then_ @
      (match else_ with Some e -> collect_blocking_calls e | None -> [])
    | _ -> []
  in
  
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
      let blocking_calls = collect_blocking_calls body in
      let count = List.length blocking_calls in
      if count >= 3 then
        collected := (Printf.sprintf
          "Function '%s' has %d sequential blocking calls — consider parallelizing with spawn/fiber"
          name count, item.item_location.start.line) :: !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Empty String Comparison
    Detects str == "" or str != "" instead of str.empty?.
    AI often generates string comparisons instead of using the idiomatic method. *)
let detect_empty_string_comparison (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EBinOp (e1, op, e2) when op = "==" || op = "!=" ->
      (match e1.expr_value, e2.expr_value with
       | ELiteral (LString ""), _ | _, ELiteral (LString "") ->
         [("Compare with empty string using .empty? instead of == \"\"", e.expr_location.start.line)]
       | _ -> []) @
      scan e1 @ scan e2
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Negated Comparison
    Detects not(x == y) instead of x != y, or not(x != y) instead of x == y.
    AI sometimes generates inverted comparisons that are harder to read. *)
let detect_negated_comparison (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EApp (fn, [arg]) when get_full_name fn = "not" || get_full_name fn = "!" ->
      (match arg.expr_value with
       | EBinOp (_, ("==" | "!=" | "<=" | ">=" | "<" | ">" | "===" as op), _) ->
         [Printf.sprintf "not(x %s y) is clearer written with the negated operator" op, e.expr_location.start.line]
       | _ -> []) @
      scan arg
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: String Concatenation in Loop
    Detects inefficient string concatenation inside iterator blocks.
    
    NOTE: Disabled for Crystal - this is an efficiency hint, not a correctness issue.
    String concatenation in loops is acceptable for small-scale operations.
*)
let detect_string_concat_loop (m : t) =
  (* Disabled for Crystal - efficiency hint, not correctness issue *)
  match m.mod_lang with
  | Crystal -> []
  | _ ->
  
  let rec find_concat_in_iter (e : expr) : (string * int) list =
    match e.expr_value with
    | EBlock es -> List.concat_map find_concat_in_iter es
    | EApp (fn, [arg]) when is_iterator_method (get_full_name fn) ->
      (match arg.expr_value with
       | EFn (_, body) -> find_concat_in_iter body
       | _ -> [])
    | EApp (fn, _) when is_string_concat (get_full_name fn) ->
      [(get_full_name fn, e.expr_location.start.line)]
    | ELet (_, _, body) -> find_concat_in_iter body
    | EIf (_, then_, else_) ->
      find_concat_in_iter then_ @ (match else_ with Some x -> find_concat_in_iter x | None -> [])
    | ECase (_, branches) -> List.concat_map (fun (_, body) -> find_concat_in_iter body) branches
    | _ -> []
  and is_iterator_method (name : string) =
    List.mem name ["each"; "map"; "select"; "reject"; "transform"; "each_with_index"]
  and is_string_concat (name : string) =
    name = "String.+" || name = "+@" || name = "+"
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := find_concat_in_iter body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(** Rule: Nilable Instance Var Access Without Check
    Detects accesses to instance variables without defensive checks.
    This is a heuristic rule - actual nil-safety depends on type declarations. *)
let detect_nilable_ivar_access (m : t) =
  
  let rec find_ivar_accesses (e : expr) : (string * int) list =
    match e.expr_value with
    | EFieldAccess ({ expr_value = EVar name; _ }, field)
      when String.length name > 0 && String.sub name 0 1 = "@" ->
      if String.length name >= 2 && String.sub name 1 1 = "@" then []
      else [(name ^ "." ^ field, e.expr_location.start.line)]
    | EVar name when String.length name > 0 && String.sub name 0 1 = "@" ->
      if String.length name >= 2 && String.sub name 1 1 = "@" then []
      else [(name, e.expr_location.start.line)]
    | EBlock es -> List.concat_map find_ivar_accesses es
    | ELet (_, _, body) -> find_ivar_accesses body
    | EApp (fn, args) ->
      List.concat_map find_ivar_accesses (fn :: args)
    | EIf (_, then_, else_) ->
      find_ivar_accesses then_ @ (match else_ with Some x -> find_ivar_accesses x | None -> [])
    | ECase (_, branches) ->
      List.concat_map (fun (_, body) -> find_ivar_accesses body) branches
    | _ -> []
  in
  let rec has_defensive_check (e : expr) : bool =
    match e.expr_value with
    | EApp (fn, _) ->
      let name = get_full_name fn in
      name = "not_nil!" || name = "try" || String.ends_with name ".try"
    | EIf (_, then_, else_) ->
      has_defensive_check then_ || (match else_ with Some x -> has_defensive_check x | None -> false)
    | ECase (_, branches) ->
      List.exists (fun (_, body) -> has_defensive_check body) branches
    | _ -> false
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      let ivar_accesses = find_ivar_accesses body in
      List.iter (fun (ivar, line) ->
        if not (has_defensive_check body) then
          collected := (Printf.sprintf "Instance var '%s' access — verify nil-safety" ivar, line) :: !collected
      ) ivar_accesses
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── Category 22: Final Sweep ─────────────────────────────────────────── *)

(** Rule: Redundant Self
    Detects explicit self. method calls where implicit self would suffice.
    AI trained on Python/Ruby often adds unnecessary self. prefixes. *)
let detect_redundant_self (m : t) =
  
  let rec scan (e : expr) =
    match e.expr_value with
    | EFieldAccess (recv, field) ->
      (match recv.expr_value with
       | EVar v when v = "self" && String.length field > 0 ->
         [Printf.sprintf "self.%s is redundant — method calls are implicitly on self" field, e.expr_location.start.line]
       | _ -> []) @
      scan recv
    | EBlock es -> List.concat_map scan es
    | ELet (_, e1, e2) -> scan e1 @ scan e2
    | EApp (fn, args) -> scan fn @ List.concat_map scan args
    | EIf (_, then_, else_) ->
      scan then_ @ (match else_ with Some e -> scan e | None -> [])
    | _ -> []
  in
  let collected = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
      collected := scan body @ !collected
    | _ -> ()
  ) m.mod_items;
  !collected

(* ── All Rules ──────────────────────────────────────────────────────── *)

let all () = [
  (* Ghost Scent *)
  ("hallucinated-stdlib", T.Error, detect_hallucinated_stdlib);
  ("deprecated-syntax", T.Warning, detect_deprecated_syntax);

  (* The Foreigner *)
  ("manual-loop", T.Hint, detect_manual_loop);
  ("primitive-obsession", T.Hint, detect_primitive_obsession);

  (* The Happy Path *)
  ("nil-chaser", T.Warning, detect_nil_chaser);
  ("ignored-return", T.Warning, detect_ignored_return);
  ("unsafe-pointer", T.Error, detect_unsafe_pointers);
  ("sleep-in-prod", T.Warning, detect_sleep_in_prod);

  (* The Tangle *)
  ("redundant-conversion", T.Hint, detect_redundant_conversion);

  (* The Mute Trap *)
  ("hardcoded-secrets", T.Error, detect_hardcoded_secrets);

  (* The Copier *)
  ("hardcoded-urls", T.Warning, detect_hardcoded_urls);

  (* The Confused *)
  ("blanket-rescue", T.Warning, detect_blanket_rescue);
  ("duplicate-validation", T.Hint, detect_duplicate_validation);

  (* The Looper *)
  ("magic-string", T.Hint, detect_magic_string);
  ("debug-require", T.Warning, detect_debug_require);

  (* Code Quality *)
  ("empty-catch", T.Warning, detect_empty_catch);
  ("flag-argument", T.Hint, detect_flag_argument);
  ("long-method", T.Warning, detect_long_method);

  (* Looper & Misc *)
  ("infinite-recursion", T.Error, detect_infinite_recursion);
  ("debug-print", T.Warning, detect_debug_print);
  ("string-interpolation-query", T.Error, detect_string_interpolation_in_query);

  (* Structural Complexity *)
  ("complex-conditional", T.Hint, detect_complex_conditional);
  ("message-chain", T.Hint, detect_message_chain);
  ("nested-ternary", T.Warning, detect_nested_ternary);

  (* Design Smells *)
  ("data-clump", T.Hint, detect_data_clump);
  ("feature-envy", T.Hint, detect_feature_envy);

  (* Dead Code *)
  ("dead-code-after-error", T.Warning, detect_dead_code_after_error);

  (* File Operations *)
  ("non-atomic-file-op", T.Hint, detect_non_atomic_file_op);
  ("unbounded-file-read", T.Warning, detect_unbounded_file_read);

  (* Async & DRY *)
  ("callback-hell", T.Warning, detect_callback_hell);
  ("repeated-regex", T.Hint, detect_repeated_regex);

  (* Arity *)
  ("too-many-params", T.Hint, detect_too_many_params);

  (* Exception Safety *)
  ("open-rescue", T.Warning, detect_open_rescue);
  ("missing-else", T.Hint, detect_missing_else);

  (* Control Flow Clarity *)
  ("reassignment-in-condition", T.Warning, detect_reassignment_in_condition);
  ("unreachable-code", T.Warning, detect_unreachable_code);

  (* Type & Network *)
  ("type-checker-abuse", T.Hint, detect_type_checker_abuse);
  ("hardcoded-port", T.Warning, detect_hardcoded_port);

  (* Style *)
  ("unless-with-else", T.Hint, detect_unless_with_else);

  (* Correctness *)
  ("global-variable", T.Warning, detect_global_variable);
  ("float-equality", T.Warning, detect_float_equality);

(* Idiomatic Crystal *)
  ("sequential-blocking", T.Hint, detect_sequential_blocking);
  ("empty-string-comparison", T.Hint, detect_empty_string_comparison);
  ("negated-comparison", T.Hint, detect_negated_comparison);
  ("string-concat-loop", T.Hint, detect_string_concat_loop);
  ("nilable-ivar-access", T.Hint, detect_nilable_ivar_access);

  (* Final Sweep *)
  ("redundant-self", T.Hint, detect_redundant_self);
]

(** Analyze module and return findings *)
let analyze_module (m : t) : Types.finding list =
  (* Get file path for test/exempt filtering *)
  let file_path = m.mod_path in
  let is_test = is_test_or_spec_file file_path in
  
  List.concat_map (fun (rule_id, sev, detector) ->
    (* Skip certain rules for test files *)
    if is_test && List.mem rule_id [
      "deprecated-syntax";  (* puts/p/pp are fine in tests *)
      "ignored-return";     (* return values often ignored in test helpers *)
      "primitive-obsession"; (* many params are fine in test data setup *)
      "too-many-params";
      "debug-print";
      "hallucinated-stdlib";
    ] then []
    else List.map (fun (msg, line) ->
      { Types.file = file_path;
        Types.line = line;
        Types.rule_id = rule_id;
        Types.severity = sev;
        Types.message = msg;
        Types.suggestion = None; }
    ) (detector m)
  ) (all ())
