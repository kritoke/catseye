(* src/ocaml/lib/ai_linter/elixir_rules.ml
   Elixir-specific AST rules for AI antipattern and hallucination detection.

   Categories:
   1. AI hallucinated methods (Python/Ruby/JS APIs used in Elixir)
   2. Framework confusion (Python/Ruby/Java/Go patterns in Elixir)
   3. Non-idiomatic Enum/pipeline patterns
   4. Debug leftovers (IO.inspect, dbg, IEx.pry)
 *)

open Base
module List = Stdlib.List
module String = Stdlib.String
module Hashtbl = Stdlib.Hashtbl
module Printf = Stdlib.Printf

(* String comparison operators *)
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

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
  | EBinOp (left, _, right) -> collect_app_names left @ collect_app_names right
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
  correct : string;
  category : string;
}

let hallucinated_methods : (string * method_entry) list = [
  (* Python *)
  ("strip",        { correct = "Use String.trim/1";           category = "Ghost Scent" });
  ("len",          { correct = "Use length/1";                category = "Ghost Scent" });
  ("append",       { correct = "Use [item | list] or list ++ [item]"; category = "Ghost Scent" });
  ("push",         { correct = "Use [item | list]";           category = "Ghost Scent" });
  ("pop",          { correct = "Use List.pop_at/2";           category = "Ghost Scent" });
  ("extend",       { correct = "Use list1 ++ list2";          category = "Ghost Scent" });
  ("remove",       { correct = "Use List.delete/2 or Enum.reject/2"; category = "Ghost Scent" });
  ("format",       { correct = "Use string interpolation \"#{...}\""; category = "Ghost Scent" });
  ("lower",        { correct = "Use String.downcase/1";       category = "Ghost Scent" });
  ("upper",        { correct = "Use String.upcase/1";         category = "Ghost Scent" });
  ("split",        { correct = "Use String.split/2 or String.split/3"; category = "Ghost Scent" });
  ("join",         { correct = "Use Enum.join/2";              category = "Ghost Scent" });
  ("keys",         { correct = "Use Map.keys/1";              category = "Ghost Scent" });
  ("values",       { correct = "Use Map.values/1";            category = "Ghost Scent" });
  ("update",       { correct = "Use Map.update/4";            category = "Ghost Scent" });
  ("items",        { correct = "Use Enum.to_list/1 on a map"; category = "Ghost Scent" });
  ("isinstance",   { correct = "Use match/2 or is_struct/2";  category = "Ghost Scent" });
  ("str",          { correct = "Use to_string/1 or inspect/1"; category = "Ghost Scent" });
  ("int",          { correct = "Use String.to_integer/1";     category = "Ghost Scent" });
  ("float",        { correct = "Use String.to_float/1";       category = "Ghost Scent" });
  ("bool",         { correct = "Use String.to_existing_atom/1 or == operator"; category = "Ghost Scent" });
  ("list",         { correct = "Use [] or Enum.to_list/1";    category = "Ghost Scent" });
  ("dict",         { correct = "Use %{}";                     category = "Ghost Scent" });
  ("set",          { correct = "Use MapSet.new/1";            category = "Ghost Scent" });
  ("tuple",        { correct = "Use {a, b}";                 category = "Ghost Scent" });
  ("type",         { correct = "Use is_integer/1, is_binary/1, etc."; category = "Ghost Scent" });
  ("chr",          { correct = "Use List.to_string/1";       category = "Ghost Scent" });
  ("ord",          { correct = "Use :binary.first/1";         category = "Ghost Scent" });
  ("abs",          { correct = "Use Kernel.abs/1";            category = "Ghost Scent" });
  ("min",          { correct = "Use Enum.min/1 or Kernel.min/2"; category = "Ghost Scent" });
  ("max",          { correct = "Use Enum.max/1 or Kernel.max/2"; category = "Ghost Scent" });
  ("sum",          { correct = "Use Enum.sum/1";               category = "Ghost Scent" });
  ("sorted",       { correct = "Use Enum.sort/1";              category = "Ghost Scent" });
  ("reversed",     { correct = "Use Enum.reverse/1";           category = "Ghost Scent" });
  ("enumerate",    { correct = "Use Enum.with_index/1";        category = "Ghost Scent" });
  ("zip",          { correct = "Use Enum.zip/2";               category = "Ghost Scent" });
  ("map",          { correct = "Use Enum.map/2";               category = "Ghost Scent" });
  ("filter",       { correct = "Use Enum.filter/2";            category = "Ghost Scent" });
  ("reduce",       { correct = "Use Enum.reduce/3";            category = "Ghost Scent" });
  ("any",          { correct = "Use Enum.any?/2";              category = "Ghost Scent" });
  ("all",          { correct = "Use Enum.all?/2";              category = "Ghost Scent" });
  ("find",         { correct = "Use Enum.find/2";              category = "Ghost Scent" });
  ("index",        { correct = "Use Enum.find_index/2";        category = "Ghost Scent" });
  ("print",        { correct = "Use IO.puts/1 or IO.inspect/2"; category = "Ghost Scent" });
  ("input",        { correct = "Use IO.gets/1";                category = "Ghost Scent" });
  ("open",         { correct = "Use File.read!/1 or File.open/2"; category = "Ghost Scent" });
  ("read",         { correct = "Use File.read!/1";             category = "Ghost Scent" });
  ("write",        { correct = "Use File.write!/2";            category = "Ghost Scent" });
  ("range",        { correct = "Use Enum.to_list(1..n)";       category = "Ghost Scent" });
  ("copy",         { correct = "Use the = operator (data is immutable)"; category = "Ghost Scent" });
  ("has_key",      { correct = "Use Map.has_key?/2";           category = "Ghost Scent" });
  ("get",          { correct = "Use Map.get/3 or pattern matching"; category = "Ghost Scent" });
  ("popitem",      { correct = "Use Map.pop/3";               category = "Ghost Scent" });
  ("clear",        { correct = "Use %{} (create new empty map)"; category = "Ghost Scent" });
  ("count",        { correct = "Use Enum.count/1 or Enum.count/2"; category = "Ghost Scent" });
  ("startswith",   { correct = "Use String.starts_with?/2";   category = "Ghost Scent" });
  ("endswith",     { correct = "Use String.ends_with?/2";     category = "Ghost Scent" });
  ("replace",      { correct = "Use String.replace/3";         category = "Ghost Scent" });
  ("isdigit",      { correct = "Use String.match?/2 with ~r"; category = "Ghost Scent" });
  (* Ruby *)
  ("puts",         { correct = "Use IO.puts/1";               category = "Ghost Scent" });
  ("nil?",         { correct = "Use is_nil/1";                category = "Ghost Scent" });
  ("select",       { correct = "Use Enum.filter/2";            category = "Ghost Scent" });
  ("reject",       { correct = "Use Enum.reject/2";            category = "Ghost Scent" });
  ("collect",      { correct = "Use Enum.map/2";               category = "Ghost Scent" });
  ("inject",       { correct = "Use Enum.reduce/3";            category = "Ghost Scent" });
  ("compact",      { correct = "Use Enum.reject(&is_nil/1)";   category = "Ghost Scent" });
  ("flatten",      { correct = "Use List.flatten/1";           category = "Ghost Scent" });
  ("include?",     { correct = "Use Enum.member?/2";            category = "Ghost Scent" });
  ("each",         { correct = "Use Enum.each/2";              category = "Ghost Scent" });
  ("empty?",       { correct = "Use Enum.empty?/1";            category = "Ghost Scent" });
  ("present?",     { correct = "Use not is_nil/1";             category = "Ghost Scent" });
  ("blank?",       { correct = "Use String.trim/1 == \"\"";    category = "Ghost Scent" });
  ("nil",          { correct = "Use nil (Elixir's nil)";       category = "Ghost Scent" });
  ("attr_accessor",{ correct = "Use defstruct or @type";       category = "Ghost Scent" });
  ("require",      { correct = "Use alias, import, or require"; category = "Ghost Scent" });
  ("class",        { correct = "Use defmodule";                category = "Ghost Scent" });
  ("def",          { correct = "Use def or defp";             category = "Ghost Scent" });
  ("lambda",       { correct = "Use fn or &";                  category = "Ghost Scent" });
  ("proc",         { correct = "Use fn or &Function.identity/0"; category = "Ghost Scent" });
  ("chomp",        { correct = "Use String.trim_trailing/1";   category = "Ghost Scent" });
  ("to_s",         { correct = "Use to_string/1";              category = "Ghost Scent" });
  ("to_i",         { correct = "Use String.to_integer/1";      category = "Ghost Scent" });
  ("to_f",         { correct = "Use String.to_float/1";        category = "Ghost Scent" });
  ("upcase",       { correct = "Use String.upcase/1";          category = "Ghost Scent" });
  ("downcase",     { correct = "Use String.downcase/1";        category = "Ghost Scent" });
  ("split",        { correct = "Use String.split/2";           category = "Ghost Scent" });
  ("join",         { correct = "Use Enum.join/2";              category = "Ghost Scent" });
  ("first",        { correct = "Use List.first/1";             category = "Ghost Scent" });
  ("last",         { correct = "Use List.last/1";              category = "Ghost Scent" });
  ("shuffle",      { correct = "Use Enum.shuffle/1";           category = "Ghost Scent" });
  ("sample",       { correct = "Use Enum.take_random/2";       category = "Ghost Scent" });
  ("uniq",         { correct = "Use Enum.uniq/1";              category = "Ghost Scent" });
  ("combination",  { correct = "Use Enum.chunk_every/2 or combinatorics"; category = "Ghost Scent" });
  ("permutation",  { correct = "Use a combinatorics library";  category = "Ghost Scent" });
  ("sort_by",      { correct = "Use Enum.sort_by/2";           category = "Ghost Scent" });
  ("group_by",     { correct = "Use Enum.group_by/2";          category = "Ghost Scent" });
  ("each_with_index", { correct = "Use Enum.with_index/2";     category = "Ghost Scent" });
  ("map_with_index", { correct = "Use Enum.with_index/1 |> Enum.map/2"; category = "Ghost Scent" });
  ("respond_to?",  { correct = "Use function_exported?/3";     category = "Ghost Scent" });
  ("is_a?",        { correct = "Use match/2 or is_struct/2";   category = "Ghost Scent" });
  ("instance_of?",  { correct = "Use match/2 or is_struct/2";  category = "Ghost Scent" });
  ("raise",        { correct = "Use raise/1 (Elixir's built-in)"; category = "Happy Path" });
  ("catch",        { correct = "Use try/rescue";              category = "Ghost Scent" });
  ("throw",        { correct = "Use throw/1 (Elixir's built-in)"; category = "Happy Path" });
  (* JavaScript *)
  ("console.log",  { correct = "Use IO.puts/1 or IO.inspect/2"; category = "Ghost Scent" });
  ("console.debug",{ correct = "Use IO.inspect/2 or Logger.debug/2"; category = "Ghost Scent" });
  ("console.error",{ correct = "Use IO.puts(:stderr, ...) or Logger.error/2"; category = "Ghost Scent" });
  ("array_push",   { correct = "Use [item | list]";            category = "Ghost Scent" });
  ("array_pop",    { correct = "Use List.pop_at/2";            category = "Ghost Scent" });
  ("array_shift",  { correct = "Use tl/1";                     category = "Ghost Scent" });
  ("array_unshift",{ correct = "Use [item | list]";            category = "Ghost Scent" });
  ("array_splice", { correct = "Use List.insert_at/3";         category = "Ghost Scent" });
  ("array_slice",  { correct = "Use Enum.slice/2";             category = "Ghost Scent" });
  ("array_concat", { correct = "Use list1 ++ list2";           category = "Ghost Scent" });
  ("array_join",   { correct = "Use Enum.join/2";              category = "Ghost Scent" });
  ("array_indexof",{ correct = "Use Enum.find_index/2";        category = "Ghost Scent" });
  ("array_includes",{ correct = "Use Enum.member?/2";          category = "Ghost Scent" });
  ("array_foreach",{ correct = "Use Enum.each/2";               category = "Ghost Scent" });
  ("array_map",    { correct = "Use Enum.map/2";               category = "Ghost Scent" });
  ("array_filter", { correct = "Use Enum.filter/2";             category = "Ghost Scent" });
  ("array_reduce", { correct = "Use Enum.reduce/3";             category = "Ghost Scent" });
  ("array_find",   { correct = "Use Enum.find/2";               category = "Ghost Scent" });
  ("array_some",   { correct = "Use Enum.any?/2";               category = "Ghost Scent" });
  ("array_every",  { correct = "Use Enum.all?/2";               category = "Ghost Scent" });
  ("array_sort",   { correct = "Use Enum.sort/1";               category = "Ghost Scent" });
  ("array_reverse",{ correct = "Use Enum.reverse/1";            category = "Ghost Scent" });
  ("array_from",   { correct = "Use Enum.to_list/1";            category = "Ghost Scent" });
  ("object_keys",  { correct = "Use Map.keys/1";               category = "Ghost Scent" });
  ("object_values",{ correct = "Use Map.values/1";             category = "Ghost Scent" });
  ("object_entries",{ correct = "Use Enum.to_list/1 on a map"; category = "Ghost Scent" });
  ("object_assign",{ correct = "Use Map.merge/2";              category = "Ghost Scent" });
  ("object_hasown",{ correct = "Use Map.has_key?/2";           category = "Ghost Scent" });
  ("typeof",       { correct = "Use is_integer/1, is_binary/1, is_list/1, etc."; category = "Ghost Scent" });
  ("instanceof",  { correct = "Use is_struct/2 or match/2";   category = "Ghost Scent" });
  ("null",         { correct = "Use nil";                      category = "Ghost Scent" });
  ("undefined",    { correct = "Use nil";                      category = "Ghost Scent" });
  ("true",         { correct = "Use true (Elixir's built-in)";  category = "Happy Path" });
  ("false",        { correct = "Use false (Elixir's built-in)"; category = "Happy Path" });
  ("Math.random",  { correct = "Use :rand.uniform/1";          category = "Ghost Scent" });
  ("Math.floor",   { correct = "Use Float.floor/1 or div/2";  category = "Ghost Scent" });
  ("Math.ceil",    { correct = "Use Float.ceil/1";             category = "Ghost Scent" });
  ("Math.round",   { correct = "Use Kernel.round/1";           category = "Ghost Scent" });
  ("Math.abs",     { correct = "Use Kernel.abs/1";             category = "Ghost Scent" });
  ("Math.max",     { correct = "Use Kernel.max/2";             category = "Ghost Scent" });
  ("Math.min",     { correct = "Use Kernel.min/2";             category = "Ghost Scent" });
  ("Math.pow",     { correct = "Use :math.pow/2";              category = "Ghost Scent" });
  ("Math.sqrt",    { correct = "Use :math.sqrt/1";             category = "Ghost Scent" });
  ("parseInt",     { correct = "Use String.to_integer/1";      category = "Ghost Scent" });
  ("parseFloat",   { correct = "Use String.to_float/1";        category = "Ghost Scent" });
  ("Number.isNaN", { correct = "Use :math.isnan/1 or match with :nan"; category = "Ghost Scent" });
  ("Number.isInteger", { correct = "Use is_integer/1";        category = "Ghost Scent" });
  ("Number.isFinite", { correct = "Use is_number/1";           category = "Ghost Scent" });
  ("JSON.stringify",{ correct = "Use Jason.encode!/1 or Jason.encode/2"; category = "Ghost Scent" });
  ("JSON.parse",   { correct = "Use Jason.decode!/1 or Jason.decode/2"; category = "Ghost Scent" });
  ("Array.isArray",{ correct = "Use is_list/1";                category = "Ghost Scent" });
  ("String.charAt", { correct = "Use String.at/2";             category = "Ghost Scent" });
  ("String.charCodeAt", { correct = "Use :binary.first/1";    category = "Ghost Scent" });
  ("String.substring", { correct = "Use String.slice/2 or String.slice/3"; category = "Ghost Scent" });
  ("String.includes", { correct = "Use String.contains?/2";    category = "Ghost Scent" });
  ("String.indexOf", { correct = "Use String.split/2 and pattern matching"; category = "Ghost Scent" });
  ("String.repeat", { correct = "Use String.duplicate/2";       category = "Ghost Scent" });
  ("String.padStart",{ correct = "Use String.pad_leading/3";   category = "Ghost Scent" });
  ("String.padEnd",  { correct = "Use String.pad_trailing/3";  category = "Ghost Scent" });
  ("String.trimStart",{ correct = "Use String.trim_leading/1"; category = "Ghost Scent" });
  ("String.trimEnd", { correct = "Use String.trim_trailing/1"; category = "Ghost Scent" });
  ("String.replaceAll",{ correct = "Use String.replace/3";     category = "Ghost Scent" });
  ("String.match",  { correct = "Use Regex.run/2 or String.match?/2"; category = "Ghost Scent" });
  ("String.split", { correct = "Use String.split/2 or String.split/3"; category = "Ghost Scent" });
  ("Promise.all",   { correct = "Use Task.await_many/1";       category = "Ghost Scent" });
  ("setTimeout",    { correct = "Use Process.send_after/4";     category = "Ghost Scent" });
  ("setInterval",  { correct = "Use Process.send_after/4 in a loop or :timer.send_interval/3"; category = "Ghost Scent" });
  ("fetch",        { correct = "Use HTTPoison, Tesla, or Req"; category = "Ghost Scent" });
  (* Java *)
  ("System.out.println", { correct = "Use IO.puts/1";          category = "Ghost Scent" });
  ("System.err.println", { correct = "Use IO.puts(:stderr, ...)"; category = "Ghost Scent" });
  ("Integer.parseInt", { correct = "Use String.to_integer/1";  category = "Ghost Scent" });
  ("Double.parseDouble", { correct = "Use String.to_float/1"; category = "Ghost Scent" });
  ("ArrayList",    { correct = "Use lists (single-linked) or :array for fixed-size"; category = "Ghost Scent" });
  ("HashMap",      { correct = "Use maps %{}";                 category = "Ghost Scent" });
  ("HashSet",      { correct = "Use MapSet";                   category = "Ghost Scent" });
  ("StringBuilder",{ correct = "Use IO.iodata_to_binary/1 or <<>>"; category = "Ghost Scent" });
  ("equals",       { correct = "Use == operator";              category = "Ghost Scent" });
  ("hashCode",     { correct = "Use :erlang.phash2/1";         category = "Ghost Scent" });
  ("toString",     { correct = "Use inspect/1 or implement the Inspect protocol"; category = "Ghost Scent" });
  ("instanceof",  { correct = "Use match/2 or is_struct/2";   category = "Ghost Scent" });
  ("getClass",     { correct = "Use __struct__ or is_struct/2"; category = "Ghost Scent" });
  ("synchronized", { correct = "Use Agent or GenServer";       category = "Ghost Scent" });
  ("new",          { correct = "Elixir has no new keyword — use module functions directly"; category = "Ghost Scent" });
  ("this",         { correct = "Elixir has no this/self — use named variables"; category = "Ghost Scent" });
  ("super",        { correct = "Use super/1 in def overrides"; category = "Ghost Scent" });
  ("try-catch",    { correct = "Use try/rescue";               category = "Ghost Scent" });
  ("throws",       { correct = "Use raise/1";                  category = "Ghost Scent" });
  ("finally",      { correct = "Use try/after";                category = "Ghost Scent" });
  ("implements",   { correct = "Use @behaviour + @callback";   category = "Ghost Scent" });
  ("extends",      { correct = "Use use Module or @behaviour";  category = "Ghost Scent" });
  ("abstract",     { correct = "Use @callback in a @behaviour"; category = "Ghost Scent" });
  ("interface",    { correct = "Use @behaviour + @callback";   category = "Ghost Scent" });
  ("static",       { correct = "Use module function (def, not defp)"; category = "Ghost Scent" });
  ("final",        { correct = "Elixir data is immutable by default"; category = "Ghost Scent" });
  ("void",         { correct = "Use :ok or return the value";  category = "Ghost Scent" });
  ("char",         { correct = "Use ?a (char literal syntax)"; category = "Ghost Scent" });
  ("byte",         { correct = "Use binary syntax <<x::8>>";   category = "Ghost Scent" });
  ("short",        { correct = "Use integer directly";         category = "Ghost Scent" });
  ("long",         { correct = "Use integer directly";         category = "Ghost Scent" });
  ("float",        { correct = "Use float directly";           category = "Ghost Scent" });
  ("double",       { correct = "Use float directly";           category = "Ghost Scent" });
  ("boolean",      { correct = "Use true/false";               category = "Ghost Scent" });
  ("string",       { correct = "Use \"...\" (binary string)";  category = "Ghost Scent" });
  (* Go *)
  ("fmt.Println",  { correct = "Use IO.puts/1";               category = "Ghost Scent" });
  ("fmt.Sprintf",  { correct = "Use string interpolation \"#{...}\""; category = "Ghost Scent" });
  ("fmt.Errorf",   { correct = "Use raise/1";                  category = "Ghost Scent" });
  ("make",         { correct = "Elixir has no make — use list/map constructors"; category = "Ghost Scent" });
  ("append",       { correct = "Use [item | list]";           category = "Ghost Scent" });
  ("len",          { correct = "Use length/1";                category = "Ghost Scent" });
  ("panic",        { correct = "Use raise/1";                  category = "Ghost Scent" });
  ("recover",      { correct = "Use try/rescue";               category = "Ghost Scent" });
  ("defer",        { correct = "Use try/after";                category = "Ghost Scent" });
  ("go",           { correct = "Use Task.async/1 or spawn/1";  category = "Ghost Scent" });
  ("chan",         { correct = "Elixir has no channels — use GenServer, Agent, or Task"; category = "Ghost Scent" });
  ("goroutine",    { correct = "Use spawn/1 or Task.async/1";   category = "Ghost Scent" });
  ("nil",          { correct = "Use nil";                      category = "Ghost Scent" });
  ("true",         { correct = "Use true";                     category = "Happy Path" });
  ("false",        { correct = "Use false";                    category = "Happy Path" });
  ("nil?",         { correct = "Use is_nil/1";                category = "Ghost Scent" });
  ("copy",         { correct = "Data is immutable — no copy needed"; category = "Ghost Scent" });
  ("close",        { correct = "Use Port.close/1 or GenServer.stop/1"; category = "Ghost Scent" });
  ("delete",       { correct = "Use Map.delete/2";             category = "Ghost Scent" });
  ("interface{}",  { correct = "Elixir has no interfaces — use @behaviour"; category = "Ghost Scent" });
  ("struct",       { correct = "Use defstruct";                 category = "Ghost Scent" });
  ("package",      { correct = "Use defmodule";                category = "Ghost Scent" });
  ("import",       { correct = "Elixir uses alias, require, import, or use"; category = "Ghost Scent" });
  ("func",         { correct = "Use def or defp";             category = "Ghost Scent" });
  ("var",          { correct = "Elixir has no var — use let binding in a comprehension or normal assignment"; category = "Ghost Scent" });
  ("const",        { correct = "Use @module attribute";        category = "Ghost Scent" });
  ("if err != nil",{ correct = "Use pattern matching with {:ok, _} or {:error, _}"; category = "Ghost Scent" });
  ("errorf",       { correct = "Use raise/1 with message";     category = "Ghost Scent" });
  ("log.Fatal",    { correct = "Use Logger.critical/2 or raise/1"; category = "Ghost Scent" });
  (* PHP *)
  ("strlen",       { correct = "Use String.length/1";          category = "Ghost Scent" });
  ("strpos",       { correct = "Use :binary.match/2";          category = "Ghost Scent" });
  ("substr",       { correct = "Use String.slice/2 or String.slice/3"; category = "Ghost Scent" });
  ("implode",      { correct = "Use Enum.join/2";              category = "Ghost Scent" });
  ("explode",      { correct = "Use String.split/2";           category = "Ghost Scent" });
  ("var_dump",     { correct = "Use IO.inspect/2";             category = "Ghost Scent" });
  ("echo",         { correct = "Use IO.puts/1";               category = "Ghost Scent" });
  ("array_push",   { correct = "Use [item | list]";            category = "Ghost Scent" });
  ("array_merge",  { correct = "Use list1 ++ list2";           category = "Ghost Scent" });
  ("in_array",     { correct = "Use Enum.member?/2";           category = "Ghost Scent" });
  ("array_key_exists", { correct = "Use Map.has_key?/2";     category = "Ghost Scent" });
  ("array_keys",   { correct = "Use Map.keys/1";              category = "Ghost Scent" });
  ("array_values", { correct = "Use Map.values/1";            category = "Ghost Scent" });
  ("is_null",      { correct = "Use is_nil/1";                category = "Ghost Scent" });
  ("is_array",     { correct = "Use is_list/1";                category = "Ghost Scent" });
  ("is_string",    { correct = "Use is_binary/1";              category = "Ghost Scent" });
  ("is_int",       { correct = "Use is_integer/1";             category = "Ghost Scent" });
  ("is_float",     { correct = "Use is_float/1";               category = "Ghost Scent" });
  ("is_bool",      { correct = "Use is_boolean/1";             category = "Ghost Scent" });
  ("trim",         { correct = "Use String.trim/1";            category = "Ghost Scent" });
  ("ucfirst",      { correct = "Use String.capitalize/1";      category = "Ghost Scent" });
  ("lcfirst",      { correct = "Use String.downcase/1 then capitalize first char"; category = "Ghost Scent" });
  ("wordwrap",     { correct = "Use String.split/2 and Enum.chunk_every/2"; category = "Ghost Scent" });
  ("number_format",{ correct = "Use :erlang.float_to_binary/2 or Number.Delimit.number_to_delimited/2"; category = "Ghost Scent" });
  ("date",         { correct = "Use Date or DateTime modules"; category = "Ghost Scent" });
  ("time",         { correct = "Use :erlang.system_time/1 or System.system_time/0"; category = "Ghost Scent" });
  ("unset",        { correct = "Data is immutable — no unset needed"; category = "Ghost Scent" });
  ("isset",        { correct = "Use pattern matching with %{key: value}"; category = "Ghost Scent" });
  ("empty",        { correct = "Use Enum.empty?/1";            category = "Ghost Scent" });
]

let hallucinated_method_map : (string, method_entry) Hashtbl.t =
  let tbl = Hashtbl.create 256 in
  List.iter (fun (name, entry) -> Hashtbl.add tbl name entry) hallucinated_methods;
  tbl

(* Elixir standard library functions that are commonly misremembered *)
let elixir_hallucinated : (string * string) list = [
  ("String.trim_start", "String.trim_leading/1");
  ("String.trim_end", "String.trim_trailing/1");
  ("String.chomp", "String.trim_trailing/1");
  ("String.chop", "String.trim_trailing/1");
  ("String.to_charlist", "String.to_charlist/1");
  ("String.codepoints", "String.codepoints/1");
  ("String.graphemes", "String.graphemes/1");
  ("List.size", "length/1");
  ("Map.size", "map_size/1");
  ("Tuple.size", "tuple_size/1");
  ("Map.has_key", "Map.has_key?/2 (note the ?)");
  ("Enum.empty", "Enum.empty?/1 (note the ?)");
  ("Enum.any", "Enum.any?/2 (note the ?)");
  ("Enum.all", "Enum.all?/2 (note the ?)");
  ("Keyword.has_key", "Keyword.has_key?/2 (note the ?)");
  ("Keyword.fetch", "Keyword.fetch/2 (returns {:ok, val} or :error)");
  ("File.read", "File.read/1 (returns {:ok, content} or {:error, reason})");
  ("is_function", "is_function/1 or is_function/2");
  ("is_nil", "is_nil/1");
  ("is_atom", "is_atom/1");
  ("is_binary", "is_binary/1");
  ("is_bitstring", "is_bitstring/1");
  ("is_boolean", "is_boolean/1");
  ("is_float", "is_float/1");
  ("is_integer", "is_integer/1");
  ("is_list", "is_list/1");
  ("is_map", "is_map/1");
  ("is_tuple", "is_tuple/1");
  ("is_pid", "is_pid/1");
  ("is_port", "is_port/1");
  ("is_reference", "is_reference/1");
]

let elixir_hallucinated_map : (string, string) Hashtbl.t =
  let tbl = Hashtbl.create 32 in
  List.iter (fun (name, correction) -> Hashtbl.add tbl name correction) elixir_hallucinated;
  tbl

(* ── 1b. Framework confusion (bare language constructs) ─────────────── *)

let framework_confusion : (string * method_entry) list = [
  ("for i in range", { correct = "Use Enum.to_list/1 or comprehensions"; category = "Framework Confusion" });
  ("while True",     { correct = "Use recursion or a GenServer";        category = "Framework Confusion" });
  ("elif",           { correct = "Use cond or additional function heads"; category = "Framework Confusion" });
  ("elif",           { correct = "Use cond or additional function heads"; category = "Framework Confusion" });
  ("__init__",       { correct = "Use defstruct or a setup function"; category = "Framework Confusion" });
  ("__name__",       { correct = "Elixir has no __name__ — use __MODULE__"; category = "Framework Confusion" });
  ("__main__",       { correct = "Elixir has no __main__ — use Mix tasks"; category = "Framework Confusion" });
  ("self",           { correct = "Elixir has no self — use named variables"; category = "Framework Confusion" });
]

let framework_confusion_map : (string, method_entry) Hashtbl.t =
  let tbl = Hashtbl.create 32 in
  List.iter (fun (name, entry) -> Hashtbl.add tbl name entry) framework_confusion;
  tbl

(* ── 2. Non-idiomatic Enum patterns ──────────────────────────────────── *)

let check_hallucinated_methods (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    let last = try let i = String.rindex name '.' in String.sub name (i+1) (String.length name - i - 1) with Stdlib.Not_found -> name in
    match (Hashtbl.find_opt hallucinated_method_map name, Hashtbl.find_opt hallucinated_method_map last) with
    | Some entry, _ | _, Some entry ->
      Some { T.file = path; line; rule_id = "hallucinated-method";
        severity = T.Warning;
        message = Printf.sprintf "'%s' doesn't exist in Elixir — %s" name entry.correct;
        suggestion = Some entry.correct }
    | None, None ->
      (match Hashtbl.find_opt elixir_hallucinated_map last with
       | Some correction ->
         Some { T.file = path; line; rule_id = "hallucinated-method";
           severity = T.Hint;
           message = Printf.sprintf "'%s' may not exist — try %s" name correction;
           suggestion = Some correction }
       | None ->
         (match Hashtbl.find_opt framework_confusion_map last with
          | Some entry ->
            Some { T.file = path; line; rule_id = "framework-confusion";
              severity = T.Warning;
              message = Printf.sprintf "'%s' looks like Python/Ruby/JS — %s" name entry.correct;
              suggestion = Some entry.correct }
          | None -> None))
  ) all_apps

let check_framework_confusion (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "puts" when not (String.length name > 4) ->
      Some { T.file = path; line; rule_id = "framework-confusion";
        severity = T.Warning;
        message = "'puts' looks like Ruby — use IO.puts/1";
        suggestion = Some "IO.puts/1" }
    | _ -> None
  ) all_apps

let check_non_idiomatic_length_empty (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "length" ->
      Some { T.file = path; line; rule_id = "non-idiomatic-length-empty";
        severity = T.Hint;
        message = "length/1 == 0 is less idiomatic than Enum.empty?/1";
        suggestion = Some "Enum.empty?/1" }
    | _ -> None
  ) all_apps

let check_non_idiomatic_sort_reverse (all_apps : (string * int) list) (path : string) : T.finding list =
  let has_sort = List.exists (fun (n, _) -> n = "Enum.sort") all_apps in
  let has_reverse = List.exists (fun (n, _) -> n = "Enum.reverse") all_apps in
  if has_sort && has_reverse then
    match List.find_opt (fun (n, line) -> n = "Enum.sort") all_apps with
    | Some (_, line) ->
      [{ T.file = path; line; rule_id = "non-idiomatic-sort-reverse";
        severity = T.Hint;
        message = "Enum.sort |> Enum.reverse — use Enum.sort(:desc)";
        suggestion = Some "Enum.sort(:desc)" }]
    | None -> []
  else []

let check_identity_map (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "Enum.map" ->
      Some { T.file = path; line; rule_id = "non-idiomatic-identity-map";
        severity = T.Hint;
        message = "Enum.map(collection, fn x -> x end) is a no-op";
        suggestion = Some "Remove the unnecessary Enum.map call" }
    | _ -> None
  ) all_apps

let check_reduce_sum (all_apps : (string * int) list) (path : string) : T.finding list =
  let has_reduce = List.exists (fun (n, _) -> n = "Enum.reduce") all_apps in
  if has_reduce then
    match List.find_opt (fun (n, line) -> n = "Enum.reduce") all_apps with
    | Some (_, line) ->
      [{ T.file = path; line; rule_id = "non-idiomatic-reduce-sum";
        severity = T.Hint;
        message = "Enum.reduce with acc + x pattern — use Enum.sum/1";
        suggestion = Some "Enum.sum/1" }]
    | None -> []
  else []

let check_reduce_count (all_apps : (string * int) list) (path : string) : T.finding list =
  let has_reduce = List.exists (fun (n, _) -> n = "Enum.reduce") all_apps in
  if has_reduce then
    match List.find_opt (fun (n, line) -> n = "Enum.reduce") all_apps with
    | Some (_, line) ->
      [{ T.file = path; line; rule_id = "non-idiomatic-reduce-count";
        severity = T.Hint;
        message = "Enum.reduce with conditional increment — use Enum.count/2";
        suggestion = Some "Enum.count/2" }]
    | None -> []
  else []

let check_reduce_frequencies (all_apps : (string * int) list) (path : string) : T.finding list =
  let has_reduce = List.exists (fun (n, _) -> n = "Enum.reduce") all_apps in
  let has_map_update = List.exists (fun (n, _) -> n = "Map.update") all_apps in
  if has_reduce && has_map_update then
    match List.find_opt (fun (n, line) -> n = "Enum.reduce") all_apps with
    | Some (_, line) ->
      [{ T.file = path; line; rule_id = "non-idiomatic-reduce-frequencies";
        severity = T.Hint;
        message = "Enum.reduce with Map.update counter pattern — use Enum.frequencies/1";
        suggestion = Some "Enum.frequencies/1" }]
    | None -> []
  else []

(* ── 3. Debug left overs ──────────────────────────────────────────────── *)

let check_debug_leftovers (all_apps : (string * int) list) (path : string) : T.finding list =
  List.filter_map (fun (name, line) ->
    match name with
    | "IO.inspect" ->
      Some { T.file = path; line; rule_id = "debug-leftover";
        severity = T.Hint;
        message = "IO.inspect/2 left in code — remove before production";
        suggestion = Some "Remove IO.inspect or use Logger.debug/2 for structured logging" }
    | "dbg" ->
      Some { T.file = path; line; rule_id = "debug-leftover";
        severity = T.Hint;
        message = "dbg/1 left in code — remove before production";
        suggestion = Some "Remove dbg call" }
    | "IEx.pry" ->
      Some { T.file = path; line; rule_id = "debug-leftover";
        severity = T.Hint;
        message = "IEx.pry/0 left in code — remove before production";
        suggestion = Some "Remove IEx.pry call" }
    | "IO.puts" ->
      Some { T.file = path; line; rule_id = "debug-leftover";
        severity = T.Hint;
        message = "IO.puts/1 may be a debug leftover — consider Logger.info/2 for production";
        suggestion = Some "Use Logger.info/1 or Logger.debug/1" }
    | _ -> None
  ) all_apps

(* ── Entry point ──────────────────────────────────────────────────────── *)

let analyze_module (mod_ : Catseye_ast.Types.t) : T.finding list =
  let all_apps = walk_items_for_apps mod_.mod_items in
  let path = mod_.mod_path in

  let hallucinations = check_hallucinated_methods all_apps path in
  let framework = check_framework_confusion all_apps path in
  let enum_patterns = check_non_idiomatic_length_empty all_apps path
    @ check_non_idiomatic_sort_reverse all_apps path
    @ check_identity_map all_apps path
    @ check_reduce_sum all_apps path
    @ check_reduce_count all_apps path
    @ check_reduce_frequencies all_apps path in
  let debug = check_debug_leftovers all_apps path in

  hallucinations @ framework @ enum_patterns @ debug
