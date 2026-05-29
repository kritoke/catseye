(* Test fixture: OCaml Unsafe Operations *)
(* This file contains Obj.magic and Marshal patterns that should trigger ocaml_unsafe.kdl *)

(* VULNERABLE: Type erasure via Obj.magic *)
let unsafe_cast_int_to_string x =
  (Obj.magic x : string)

(* VULNERABLE: Generic type coercion *)
let unsafe_coerce value target_type =
  let repr = Obj.repr value in
  Obj.obj repr

(* VULNERABLE: Object mutation *)
let unsafe_object_set obj field value =
  Obj.set obj field (Obj.repr value)

(* VULNERABLE: Marshal deserialization from file *)
let unsafe_unmarshal_file path =
  let content = Stdlib.In_channel.with_open_text path Stdlib.In_channel.input_all in
  Marshal.from_string content 0

(* VULNERABLE: Marshal from channel *)
let unsafe_unmarshal_channel ic =
  Marshal.from_channel ic

(* VULNERABLE: Marshal from string with untrusted input *)
let unmarshal_untrusted data =
  Marshal.from_string data 0

(* VULNERABLE: unsafe_yojson bypassing validation *)
type config = { name: string; value: int } [@@deriving unsafe_yojson]

(* SAFE: Type-safe JSON serialization *)
let safe_json_parse json =
  Yojson.Safe.from_string json

(* SAFE: Explicit type validation *)
let safe_parse_with_validation json =
  match Yojson.Safe.from_string json with
  | `Assoc items ->
    let name = List.assoc "name" items |> Yojson.Util.to_string in
    let value = List.assoc "value" items |> Yojson.Util.to_int in
    Ok { name; value }
  | _ -> Error "Invalid JSON structure"

(* SAFE: Using sexplib with typed conversions *)
let safe_sexp_parse sexp_str =
  let sexp = Sexplib.Sexp.of_string sexp_str in
  Config_of_sexp.t_of_sexp sexp

(* SAFE: HMAC-verified Marshal (still risky but better) *)
let safer_unmarshal_with_hmac data expected_hmac =
  let computed = Digest.to_hex (Digest.string data) in
  if computed = expected_hmac then
    Some (Marshal.from_string data 0)
  else
    None
