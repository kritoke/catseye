(* lib/catseye_engine/string_utils.ml *)

(** String utilities for case-insensitive matching and pattern detection.
    Replaces 200+ lines of manual string matching across codebase. *)

open Base

(* Expose stdlib equality that Base shadows *)
let ( = ) = Stdlib.( = )

(* Test file patterns *)
let test_suffixes = ["_test"; "_tests"; ".test"; ".tests"; "_spec"; "_specs"; ".spec"; ".specs"]
let test_prefixes = ["test_"; "tests_"; "spec_"; "specs_"; "test-"; "tests-"; "spec-"; "specs-"]
let test_contains = ["test"; "spec"; "_spec_"]

(** Case-insensitive suffix check. *)
let is_test_suffix (filename : string) ~(suffix_list : string list) : bool =
  let lower_filename = String.lowercase filename in
  List.exists suffix_list ~f:(fun suffix ->
    String.is_suffix ~suffix:(String.lowercase suffix) lower_filename
  )

(** Case-insensitive prefix check. *)
let is_test_prefix (filename : string) ~(prefix_list : string list) : bool =
  let lower_filename = String.lowercase filename in
  List.exists prefix_list ~f:(fun prefix ->
    String.is_prefix ~prefix:(String.lowercase prefix) lower_filename
  )

(** Case-insensitive substring (contains) check. *)
let is_containing (filename : string) ~(substring_list : string list) : bool =
  let lower_filename = String.lowercase filename in
  List.exists substring_list ~f:(fun substring ->
    String.is_substring ~substring:(String.lowercase substring) lower_filename
  )

(** Combined test file detection using suffix + prefix + contains.
    A file is considered a test file if it matches any of the criteria. *)
let is_test_file (filename : string) : bool =
  is_test_suffix filename ~suffix_list:test_suffixes
  || is_test_prefix filename ~prefix_list:test_prefixes
  || is_containing filename ~substring_list:test_contains

(** Check if a qualified name matches a prefix pattern.
    Examples:
      "HTTP::Client.get" matches "HTTP::Client"
      "Foo::Bar.method" matches "Foo::Bar"
*)
let matches_prefix (qualified_name : string) ~(pattern_list : string list) : bool =
  let lower_name = String.lowercase qualified_name in
  List.exists pattern_list ~f:(fun pattern ->
    let lower_pattern = String.lowercase pattern in
    String.is_prefix ~prefix:lower_pattern lower_name
    || String.is_prefix ~prefix:(lower_pattern ^ ".") (lower_name ^ ".")
  )

(** Check if a name matches a suffix pattern (exact or suffix match).
    Examples:
      "readFileSync" matches "readFileSync"
      "foo_readFileSync" matches "readFileSync"
*)
let matches_suffix (name : string) ~(pattern_list : string list) : bool =
  let lower_name = String.lowercase name in
  List.exists pattern_list ~f:(fun pattern ->
    let lower_pattern = String.lowercase pattern in
    (String.equal lower_name lower_pattern)
    || String.is_suffix ~suffix:lower_pattern lower_name
  )

(** Count occurrences of a substring in a string.
    Used for complexity metrics like logical operator counting. *)
let count_substring (text : string) ~(substring : string) : int =
  if String.is_empty substring then 0
  else
    let rec aux pos count =
      match String.substr_index ~pos text ~pattern:substring with
      | Some idx -> aux (idx + String.length substring) (count + 1)
      | None -> count
    in
    aux 0 0

(** Safe string take - returns min(length, n) chars from start.
    Prevents out-of-bounds errors when n > string length. *)
let safe_take (s : string) (n : int) : string =
  if n <= 0 then ""
  else if n >= String.length s then s
  else String.prefix s n

(** Split a string on a character delimiter. *)
let split (s : string) ~(on : char) : string list =
  String.split s ~on

(** Strip leading/trailing whitespace. *)
let strip (s : string) : string =
  String.strip s