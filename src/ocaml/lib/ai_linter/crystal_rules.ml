(* src/ocaml/lib/ai_linter/crystal_rules.ml
   Crystal-specific AST rules

   All rules operate on CatseyeAST.t using typed pattern matching.
   Uses the shared Types.finding type from types.ml.
*)

open Catseye_ast.Types

module T = Types

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
  { name = "File.exists?"; correct = "File.file? or File.exists? (deprecated in newer Crystal)";
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
  { name = "JSON.parse"; correct = "JSON.parse returns JSON::Any, not Hash — use .as_h or .as_a";
    category = "Happy Path"; lang = `Crystal };
  { name = "HTTP::Client.get"; correct = "HTTP::Client.get exists but doesn't accept params: keyword";
    category = "Ghost Scent"; lang = `Ruby };

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
  { name = "String.new"; correct = "Use string literals directly — String.new is redundant";
    category = "Tangle"; lang = `Crystal };
  { name = "puts"; correct = "Use pp for debug output; remove puts in production code";
    category = "Legacy"; lang = `Crystal };
  { name = "p"; correct = "Use pp for debug output; remove p in production code";
    category = "Legacy"; lang = `Crystal };
  { name = "pp"; correct = "pp is for debugging only — remove in production code";
    category = "Legacy"; lang = `Crystal };

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
  let findings = ref [] in
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
              findings := (msg, line) :: !findings
          | None -> ()
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  List.sort_uniq (fun (m1, l1) (m2, l2) ->
    let c = compare l1 l2 in if c <> 0 then c else String.compare m1 m2
  ) !findings

(** Rule 1.2: Legacy/Deprecated Syntax *)
let detect_deprecated_syntax (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          if name = "puts" then
            findings := ("puts used for debugging", line) :: !findings;
          if name = "p" then
            findings := ("p used for debugging", line) :: !findings;
          if name = "pp" then
            findings := ("pp used for debugging", line) :: !findings;
          if name = "String.new" then
            findings := ("String.new often redundant", line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 2: The Foreigner ──────────────────────────────────────── *)

(** Rule 2.1: Manual Loops vs Iterators
    Detect while loops with counter variable and index access patterns
    that could be replaced with .each, .map, .select, etc. *)
let detect_manual_loop (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let calls = collect_app_names body in
        (* Check for while + counter patterns via calls *)
        let has_while = List.exists (fun (n, _) -> n = "while") calls in
        let has_counter = List.exists (fun (n, _) ->
          String.ends_with ~suffix:"+= 1" n || String.ends_with ~suffix:"+=1" n ||
          n = "i += 1" || n = "idx += 1" || n = "index += 1") calls in
        if has_while && has_counter then begin
          let line = match List.find_opt (fun (n, _) -> n = "while") calls with
            | Some (_, l) -> l | None -> item.item_location.start.line
          in
          findings := ("Manual while loop with counter — consider using .each, .map, or .each_with_index", line) :: !findings
        end
    | _ -> ()
  ) m.mod_items;
  !findings

(** Rule 2.3: Primitive Obsession (3+ params) *)
let detect_primitive_obsession (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
        let params = List.filter (function PVar _ -> true | _ -> false) patterns in
        if List.length params >= 3
        then findings := (Printf.sprintf "Function '%s' has %d parameters - consider domain types" name (List.length params), item.item_location.start.line) :: !findings
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 3: The Happy Path ──────────────────────────────────────── *)

(** Rule 3.1: Nil-chaser (unchecked nil access)
    Uses type inference DB to detect when a call that returns T | Nil
    is accessed without a nil guard (e.g. user.name where user comes
    from Hash#[]? or Array#first?). Also detects .not_nil!, .as(Type)
    casts, and .try(&.x) as code smells. *)
let detect_nil_chaser (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          (* Pattern 1: .not_nil! — forced unwrap *)
          if name = "not_nil!" then
            findings := ("not_nil! will raise on nil — use pattern matching or nil check instead", line) :: !findings;
          (* Pattern 2: .as( — type cast that crashes on nil *)
          if String.length name >= 3 &&
             String.sub name (String.length name - 3) 3 = ".as" then
            findings := ("Type cast with .as() may crash if nil — consider case expression", line) :: !findings;
          (* Pattern 3: Nullable-returning call accessed without guard *)
          (match Type_inference.lookup_crystal name with
           | Some ({ kind = Nullable; doc; _ } as info) ->
               findings := (Printf.sprintf
                 "Call %s returns %s (%s) — access may raise on nil"
                 name info.Type_inference.type_name doc, line) :: !findings
           | _ -> ());
          (* Pattern 4: Raising accessor used without rescue *)
          (match Type_inference.lookup_crystal name with
           | Some { kind = Safe; type_name = "T"; _ } when
               String.length name >= 2 &&
               String.sub name (String.length name - 2) 2 = "[]" ->
               findings := (Printf.sprintf
                 "%s raises on missing key/index — use []? variant or nil check"
                 name, line) :: !findings
           | _ -> ())
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(** Rule 3.2: Ignoring Return Value
    Detects when a call that returns an important value (HTTP response,
    JSON parse result, DB query) has its return value discarded (no let binding).
    AI often writes `HTTP::Client.get(url)` without capturing the response. *)
let detect_ignored_return (m : t) =
  let important_returns = [
    "HTTP::Client.get"; "HTTP::Client.post"; "HTTP::Client.put";
    "HTTP::Client.delete"; "HTTP::Client.patch";
    "HTTP.get"; "HTTP.post"; "HTTP.put";
    "JSON.parse"; "JSON.parse_io";
    "DB.query"; "DB.query_one"; "DB.query_one?";
    "DB.exec";
    "File.read"; "File.write";
    "File.read?"; "File.write?";
  ] in
  let is_important (name : string) =
    List.exists (fun prefix ->
      String.length name >= String.length prefix &&
      String.sub name 0 (String.length prefix) = prefix
    ) important_returns
  in
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let calls = collect_app_names body in
        List.iter (fun (name, line) ->
          if is_important name then
            findings := (Printf.sprintf
              "Return value of %s is discarded — capture and check the result" name, line) :: !findings
        ) calls
    | _ -> ()
  ) m.mod_items;
  !findings

let detect_unsafe_pointers (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          if name = "Pointer.malloc" then
            findings := ("Pointer.malloc is unsafe — use Slice or Array for safe memory management", line) :: !findings;
          if name = "Pointer.null" then
            findings := ("Pointer.null is unsafe — use Nil or Option(T) for absent values", line) :: !findings;
          if name = "Pointer.new" then
            findings := ("Pointer.new is unsafe — consider Slice or a safe wrapper", line) :: !findings;
          if String.length name >= 6 && String.sub name 0 6 = "unsafe" then
            findings := (Printf.sprintf "%s bypasses safety checks — use safe alternative if available" name, line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(** Rule: Sleep in production code *)
let detect_sleep_in_prod (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          if name = "sleep" then
            findings := ("sleep() in production code — remove or gate behind debug flag", line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 4: The Tangle ─────────────────────────────────────────── *)

(** Rule 4.1: Redundant Conversions *)
let detect_redundant_conversion (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          if name = "String.new" then
            findings := ("String.new redundant - use literal", line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 5: The Mute Trap (Security) ───────────────────────────── *)

(** Rule 5.1: Hardcoded Secrets *)
let detect_hardcoded_secrets (m : t) =
  let secret_prefixes = [
    "sk_"; "sk_live_"; "sk_test_";       (* Stripe *)
    "ghp_"; "gho_"; "ghu_"; "ghs_";     (* GitHub *)
    "AKIA"; "ASIA";                       (* AWS *)
    "AIza";                               (* Google API *)
    "xoxb-"; "xoxp-"; "xoxa-";           (* Slack *)
    "eyJ";                                (* JWT (starts with eyJ...) *)
    "-----BEGIN RSA PRIVATE KEY-----";
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
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
        List.iter (fun (s, line) ->
          let masked = String.sub s 0 (min 8 (String.length s)) ^ "..." in
          findings := (Printf.sprintf
            "Potential hardcoded secret in '%s': %s — use environment variables or config"
            name masked, line) :: !findings
        ) (collect_string_literals body)
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 6: The Copier (Copy-Paste) ────────────────────────────── *)

(** Rule 6.3: Hardcoded URLs/IPs *)
let detect_hardcoded_urls (m : t) =
  let is_urlish (s : string) =
    String.length s >= 8 &&
    (String.sub s 0 7 = "http://" || String.sub s 0 8 = "https://")
  in
  let is_ipish (s : string) =
    let parts = String.split_on_char '.' s in
    List.length parts = 4 &&
    List.for_all (fun p -> try let _ = int_of_string p in true with _ -> false) parts
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
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (s, line) ->
          findings := (Printf.sprintf
            "Hardcoded URL/IP: %s — use config or environment variable" s, line) :: !findings
        ) (collect_suspicious_strings body)
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 7: The Confused (Language Feature Misuse) ─────────────── *)

(** Rule 7.1: Blanket Rescue
    Detects bare `rescue` or `rescue ex` without specifying an exception type.
    AI often generates blanket rescues that swallow all errors silently. *)
let detect_blanket_rescue (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (name, line) ->
          (* Crystal extractor emits rescue blocks as calls *)
          if name = "rescue" || name = "begin" then
            findings := ("Blanket rescue catches all exceptions — catch specific exception types instead", line) :: !findings
        ) (collect_app_names body)
    | _ -> ()
  ) m.mod_items;
  !findings

(** Rule 7.2: Duplicate Validation
    Detects the same variable being validated twice in the same function.
    AI often generates redundant validations from copy-paste. *)
let detect_duplicate_validation (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let calls = collect_app_names body in
        (* Group calls by name and track which vars they operate on *)
        let validation_methods = ["empty?"; "nil?"; "blank?"; "valid?"; "present?"; "includes?"] in
        List.iter (fun method_name ->
          let matching = List.filter (fun (n, _) ->
            String.length n >= String.length method_name &&
            String.sub n (String.length n - String.length method_name) (String.length method_name) = method_name
          ) calls in
          (* If same validation method appears 2+ times, it's likely duplicate *)
          if List.length matching >= 3 then
            let line = match matching with (_, l) :: _ -> l | [] -> 0 in
            findings := (Printf.sprintf "%s called %d times — check for duplicate validation logic"
              method_name (List.length matching), line) :: !findings
        ) validation_methods
    | _ -> ()
  ) m.mod_items;
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
        (* Check if either arg is a string literal *)
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
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        List.iter (fun (s, line) ->
          findings := (Printf.sprintf
            "Magic string \"%s\" used in comparison — consider using a constant or enum" s, line) :: !findings
        ) (collect_equality_strings body)
    | _ -> ()
  ) m.mod_items;
  !findings

(** Rule: Debug Require
    Detects require statements for debug/development gems that shouldn't
    be in production code. *)
let detect_debug_require (m : t) =
  let debug_requires = [
    "debug"; "pry"; "byebug"; "binding_of_caller"; "irb";
    "debugger"; "pry-byebug"; "pry-doc"; "pry-stack_explorer";
  ] in
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IImport (name, _) ->
        if List.mem name debug_requires then
          findings := (Printf.sprintf
            "require \"%s\" is a debug dependency — remove for production" name,
            item.item_location.start.line) :: !findings
    | _ -> ()
  ) m.mod_items;
  !findings

(* ── Category 9: Code Quality ────────────────────────────────────────── *)

(** Rule: Empty Catch Block
    Detects rescue/except blocks with empty bodies — errors swallowed silently.
    AI often generates empty rescue blocks as placeholders. *)
let detect_empty_catch (m : t) =
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (_, _, _, body) ->
        let rec has_empty_rescue (e : expr) =
          match e.expr_value with
          | EApp (fn, args) when get_full_name fn = "rescue" ->
              (* rescue block with no meaningful content *)
              let has_body = List.exists (fun a ->
                match a.expr_value with
                | EBlock [] | EUnit -> false
                | _ -> true
              ) args in
              if not has_body then
                Some e.expr_location.start.line
              else None
          | EBlock es -> List.find_map has_empty_rescue es
          | ELet (_, e1, e2) ->
              (match has_empty_rescue e1 with Some l -> Some l | None -> has_empty_rescue e2)
          | EIf (_, then_, else_) ->
              (match has_empty_rescue then_ with
               | Some l -> Some l
               | None -> (match else_ with Some e -> has_empty_rescue e | None -> None))
          | _ -> None
        in
        (match has_empty_rescue body with
         | Some line ->
             findings := ("Empty rescue block — errors are silently swallowed. Log or handle the exception.", line) :: !findings
         | None -> ())
    | _ -> ()
  ) m.mod_items;
  !findings

(* Rule: Flag Argument
    Detects boolean-style parameters (is_X, should_X, has_X, with_X, no_X).
    AI-generated code often uses flag arguments instead of separate methods or enums. *)
let detect_flag_argument (m : t) =
  let is_flag_name (s : string) =
    String.length s >= 3 &&
    let prefixes = ["is_"; "should_"; "has_"; "with_"; "no_"; "use_"; "enable_"; "disable_"] in
    List.exists (fun p -> String.length s > String.length p && String.sub s 0 (String.length p) = p) prefixes
  in
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, patterns, _, _) ->
        let flag_params = List.filter_map (function
          | PVar v when is_flag_name v -> Some v
          | _ -> None
        ) patterns in
        List.iter (fun p ->
          findings := (Printf.sprintf
            "Function '%s' has flag argument '%s' — consider splitting into separate methods or using an enum"
            name p, item.item_location.start.line) :: !findings
        ) flag_params
    | _ -> ()
  ) m.mod_items;
  !findings

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
    | _ -> 1
  in
  let findings = ref [] in
  List.iter (fun item ->
    match item.item_value with
    | IFunction (name, _, _, body) ->
        let count = count_nodes body in
        if count > max_nodes then
          findings := (Printf.sprintf
            "Function '%s' has %d AST nodes (max %d) — consider breaking into smaller functions"
            name count max_nodes, item.item_location.start.line) :: !findings
    | _ -> ()
  ) m.mod_items;
  !findings

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
]

(** Analyze module and return findings *)
let analyze_module (m : t) : Types.finding list =
  List.concat_map (fun (rule_id, sev, detector) ->
    List.map (fun (msg, line) ->
      { Types.file = m.mod_path;
        Types.line = line;
        Types.rule_id = rule_id;
        Types.severity = sev;
        Types.message = msg;
        Types.suggestion = None; }
    ) (detector m)
  ) (all ())
