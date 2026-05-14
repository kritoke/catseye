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

(** Rule 2.1: Manual Loops vs Iterators *)
let detect_manual_loop (_m : t) =
  (* TODO: Detect while loops that could be iterators *)
  []

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

(** Rule 3.1: Nil-chaser (unchecked nil access) *)
let detect_nil_chaser (_m : t) =
  (* TODO: Requires type info from Crystal worker *)
  []

(** Rule 3.3: Unsafe Pointers *)
let detect_unsafe_pointers (_m : t) =
  (* TODO: Detect Pointer usage not in @[Safe] context *)
  []

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
  ("unsafe-pointer", T.Error, detect_unsafe_pointers);

  (* The Tangle *)
  ("redundant-conversion", T.Hint, detect_redundant_conversion);

  (* The Mute Trap *)
  ("hardcoded-secrets", T.Error, detect_hardcoded_secrets);

  (* The Copier *)
  ("hardcoded-urls", T.Warning, detect_hardcoded_urls);
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
