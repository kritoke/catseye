(* src/ocaml/lib/ai_linter/type_inference.ml
   Simple local type inference for AI linter rules.

   Uses a known-return-types database to track what Crystal/Gleam
   functions return, without needing a full type checker.

   Approach: "Option B" — a database of known return types for stdlib
   and common library functions. Variables assigned from these calls
   inherit the return type. *)

open Base
module Hashtbl = Stdlib.Hashtbl
module String = Stdlib.String
module Option = Stdlib.Option
module List = Stdlib.List

(* ── Return type classification ────────────────────────────────────── *)

type return_kind =
  | Nullable    (** Returns T | Nil — e.g. Hash#[]?, Array#first? *)
  | Result      (** Returns Result(a, b) — Gleam functions that can fail *)
  | Safe        (** Returns T (never nil/error) *)
  | Unknown     (** No type info available *)

type type_info = {
  kind : return_kind;
  type_name : string;  (* e.g. "String | Nil", "Result(User, String)" *)
  doc : string;        (* Short explanation for messages *)
}

(* ── Crystal known return types ────────────────────────────────────── *)

let crystal_return_types : (string, type_info) Hashtbl.t =
  let tbl = Hashtbl.create 128 in
  let add names info = List.iter (fun n -> Hashtbl.replace tbl n info) names in

  (* Nilable accessors *)
  add ["Hash#[]?"; "Array#first?"; "Array#last?"; "Array#[]?"]
    { kind = Nullable; type_name = "T | Nil";
      doc = "Returns nil when key/index not found" };

  (* Raising accessors — these DO return T, but crash on missing *)
  add ["Hash#[]"; "Array#first"; "Array#last"; "Array#[]"]
    { kind = Safe; type_name = "T";
      doc = "Raises KeyError/IndexError when not found" };

  (* JSON — returns JSON::Any, not Hash *)
  add ["JSON.parse"; "JSON.parse_io"]
    { kind = Safe; type_name = "JSON::Any";
      doc = "Returns JSON::Any — use .as_h, .as_a, .as_s to get typed value" };

  (* HTTP — returns Response, not body *)
  add ["HTTP::Client.get"; "HTTP::Client.post"; "HTTP::Client.put";
       "HTTP::Client.delete"; "HTTP::Client.patch"; "HTTP::Client.head";
       "HTTP::Client.get"; "HTTP::Client.post"]
    { kind = Safe; type_name = "HTTP::Client::Response";
      doc = "Returns HTTP::Client::Response — use .body, .status_code" };

  (* DB — common nilable returns *)
  add ["DB.query_one?"; "Repo.get?"]
    { kind = Nullable; type_name = "T | Nil";
      doc = "Returns nil when no row found" };

  (* File — nilable reads *)
  add ["File.read?"]
    { kind = Nullable; type_name = "String | Nil";
      doc = "Returns nil when file not found" };

  (* Regex match *)
  add ["Regex.match?"; "String.match?"]
    { kind = Nullable; type_name = "MatchData | Nil";
      doc = "Returns nil when no match" };

  (* Type conversions that preserve type *)
  add ["to_s"] { kind = Safe; type_name = "String"; doc = "Returns String" };
  add ["to_i"] { kind = Safe; type_name = "Int32"; doc = "Returns Int32" };
  add ["to_f"] { kind = Safe; type_name = "Float64"; doc = "Returns Float64" };
  add ["to_h"] { kind = Safe; type_name = "Hash"; doc = "Returns Hash" };
  add ["to_a"] { kind = Safe; type_name = "Array"; doc = "Returns Array" };

  tbl

(* ── Gleam known return types ──────────────────────────────────────── *)

let gleam_return_types : (string, type_info) Hashtbl.t =
  let tbl = Hashtbl.create 64 in
  let add names info = List.iter (fun n -> Hashtbl.replace tbl n info) names in

  (* Functions returning Result *)
  add ["int.parse"; "float.parse"]
    { kind = Result; type_name = "Result(Int, Nil)";
      doc = "Returns Result — must handle Error case" };

  add ["file.read"; "file.write"]
    { kind = Result; type_name = "Result(String, reason)";
      doc = "Returns Result — file operations can fail" };

  add ["http.send"; "http.get"]
    { kind = Result; type_name = "Result(Response, error)";
      doc = "Returns Result — HTTP requests can fail" };

  add ["dict.get"]
    { kind = Result; type_name = "Result(value, Nil)";
      doc = "Returns Result — key may not exist" };

  (* Functions returning Option *)
  add ["list.first"; "list.last"]
    { kind = Nullable; type_name = "Option(a)";
      doc = "Returns Option — list may be empty" };

  add ["map.get"]
    { kind = Nullable; type_name = "Option(value)";
      doc = "Returns Option — key may not exist" };

  tbl

(* ── Lookup helpers ────────────────────────────────────────────────── *)

(** Look up a Crystal call name. Tries full name first, then suffix.
    E.g. "HTTP::Client.get" matches directly, "client.get" matches "get"
    as a suffix fallback. *)
let lookup_crystal (name : string) : type_info option =
  (* Direct match *)
  match Hashtbl.find_opt crystal_return_types name with
  | Some info -> Some info
  | None ->
    (* Suffix match: "client.get" → try "get" *)
    (match String.rindex_opt name '.' with
     | Some idx ->
         let suffix = String.sub name (idx + 1) (String.length name - idx - 1) in
         Hashtbl.find_opt crystal_return_types suffix
     | None -> None)

(** Look up a Gleam call name *)
let lookup_gleam (name : string) : type_info option =
  match Hashtbl.find_opt gleam_return_types name with
  | Some info -> Some info
  | None ->
    (* Try module.function → just function *)
    (match String.rindex_opt name '.' with
     | Some idx ->
         let suffix = String.sub name (idx + 1) (String.length name - idx - 1) in
         Hashtbl.find_opt gleam_return_types suffix
     | None -> None)

(** Check if a call returns a nullable type *)
let returns_nullableCrystal ?(lang = "crystal") (name : string) : bool =
  match lang with
  | "crystal" -> (match lookup_crystal name with
      | Some { kind = Nullable; _ } -> true | _ -> false)
  | "gleam" -> (match lookup_gleam name with
      | Some { kind = Nullable; _ } | Some { kind = Result; _ } -> true | _ -> false)
  | _ -> false

(** Check if a call returns a Result type (Gleam) *)
let returns_result (name : string) : bool =
  match lookup_gleam name with
  | Some { kind = Result; _ } -> true | _ -> false

(** Get type info for a call *)
let get_type_info ~(lang : string) (name : string) : type_info option =
  match lang with
  | "crystal" -> lookup_crystal name
  | "gleam" -> lookup_gleam name
  | _ -> None
