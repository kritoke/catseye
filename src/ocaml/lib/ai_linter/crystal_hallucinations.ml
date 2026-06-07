(* src/ocaml/lib/ai_linter/crystal_hallucinations.ml
   Hallucinated Crystal method database

   Curated knowledge base of methods that don't exist in Crystal but AI
   often suggests (confusing them with Ruby, JS, Elixir, or deprecated
   Crystal patterns). Used by detect_hallucinated_stdlib in
   crystal_rules_ghost.ml.
 *)

open Base
module List = Stdlib.List
module String = Stdlib.String
module Hashtbl = Stdlib.Hashtbl

(* String comparison operators *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

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
