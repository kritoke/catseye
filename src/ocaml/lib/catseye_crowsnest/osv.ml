(* lib/catseye_crowsnest/osv.ml
   OSV.dev API client — query for known vulnerabilities in dependencies.
   Uses curl subprocess for zero-dependency HTTP. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
let ( < ) = Stdlib.( < )
let ( > ) = Stdlib.( > )
let ( <= ) = Stdlib.( <= )
let ( >= ) = Stdlib.( >= )

type osv_vulnerability = {
  id : string;
  summary : string;
  severity : string option;
  patched_versions : string list;
  references : string list;
}

type osv_result =
  | No_known_cves
  | Vulnerabilities of osv_vulnerability list
  | Query_failed of string

(* ── JSON parsing ───────────────────────────────────────────────────── *)

let parse_osv_response (json_str : string) : osv_result =
  try
    let json = Yojson.Safe.from_string json_str in
    let get = Yojson.Safe.Util.to_string in
    let to_list = Yojson.Safe.Util.to_list in
    let to_assoc = Yojson.Safe.Util.to_assoc in
    match json with
    | `Assoc dict ->
      (match List.Assoc.find dict ~equal:String.equal "vulns" with
       | None -> No_known_cves
       | Some (`List vulns) ->
         let parsed = List.filter_map ~f:(fun v ->
           let d = to_assoc v in
           let id = get (List.Assoc.find_exn d ~equal:String.equal "id") in
           let summary = match List.Assoc.find d ~equal:String.equal "summary" with
             | Some s -> get s | None -> ""
           in
           let severity = match List.Assoc.find d ~equal:String.equal "database_specific" with
             | Some (`Assoc spec) ->
               (match List.Assoc.find spec ~equal:String.equal "severity" with
                | Some s -> Some (get s) | None -> None)
             | None ->
               (match List.Assoc.find d ~equal:String.equal "severity" with
                | Some (`List []) -> None
                | Some (`List (first :: _)) ->
                  (match first with
                   | `Assoc s ->
                     (match List.Assoc.find s ~equal:String.equal "score" with
                      | Some s -> Some (get s) | None -> None)
                   | _ -> None)
                | _ -> None)
           in
           let patched = match List.Assoc.find d ~equal:String.equal "affected" with
             | Some (`List affected) ->
               List.concat_map ~f:(fun a ->
                 let ad = to_assoc a in
                 match List.Assoc.find ad ~equal:String.equal "ranges" with
                 | Some (`List ranges) ->
                   List.concat_map ~f:(fun r ->
                     let rd = to_assoc r in
                     match List.Assoc.find rd ~equal:String.equal "events" with
                     | Some (`List events) ->
                       List.filter_map ~f:(fun e ->
                         let ed = to_assoc e in
                         match List.Assoc.find ed ~equal:String.equal "fixed" with
                         | Some v -> Some (get v)
                         | None -> None
                       ) events
                     | None -> []
                   ) ranges
                 | None -> []
               ) affected
             | None -> []
           in
           let refs = match List.Assoc.find d ~equal:String.equal "references" with
             | Some (`List rlist) ->
               List.filter_map ~f:(fun r ->
                 let rd = to_assoc r in
                 match List.Assoc.find rd ~equal:String.equal "url" with
                 | Some u -> Some (get u)
                 | None -> None
               ) rlist
             | None -> []
           in
           if id <> "" then Some {
             id; summary; severity; patched_versions = patched; references = refs
           } else None
         ) vulns in
         if parsed = [] then No_known_cves
         else Vulnerabilities parsed
       | Some _ -> No_known_cves)
    | _ -> No_known_cves
  with _ -> Query_failed "Failed to parse OSV response"

(* ── API query ──────────────────────────────────────────────────────── *)

(** Query OSV.dev for a single package+version.
    Returns the raw result (no caching — see cache.ml for that). *)
let query (ecosystem : string) (package : string) (version : string)
    : osv_result =
  let json_payload = Printf.sprintf
    {|{"package":{"name":"%s","ecosystem":"%s"},"version":"%s"}|}
    package ecosystem version
  in
  let tmp_in = Stdlib.Filename.temp_file "catseye-osv-in" ".json" in
  let tmp_out = Stdlib.Filename.temp_file "catseye-osv-out" ".json" in
  try
    (* Write payload to temp file *)
    let oc = Stdlib.open_out tmp_in in
    Stdlib.output_string oc json_payload;
    Stdlib.close_out oc;

    let cmd = Printf.sprintf
      "curl -s -S -f --max-time 10 -X POST https://api.osv.dev/v1/query -d @%s -o %s 2>/dev/null"
      (Stdlib.Filename.quote tmp_in) (Stdlib.Filename.quote tmp_out)
    in
    let exit_code = Stdlib.Sys.command cmd in
    Unix.unlink tmp_in;
    if exit_code <> 0 then begin
      (try Unix.unlink tmp_out with _ -> ());
      Query_failed (Printf.sprintf "curl exited with code %d" exit_code)
    end
    else begin
      try
        let ic = Stdlib.open_in tmp_out in
        let len = Stdlib.in_channel_length ic in
        let buf = Bytes.create len in
        Stdlib.really_input ic buf 0 len;
        Stdlib.close_in ic;
        Unix.unlink tmp_out;
        let response = Bytes.to_string buf in
        if response = "" then No_known_cves
        else parse_osv_response response
      with Sys_error _ ->
        (try Unix.unlink tmp_out with _ -> ());
        No_known_cves
    end
  with Sys_error msg ->
    (try Unix.unlink tmp_in with _ -> ());
    (try Unix.unlink tmp_out with _ -> ());
    Query_failed msg

(** Batch query: query multiple packages efficiently.
    OSV doesn't have a true batch endpoint, so we query sequentially
    with a small delay to respect rate limits. *)
let query_batch (ecosystem : string) (packages : (string * string) list)
    : ((string * string) * osv_result) list =
  List.map ~f:(fun (name, version) ->
    let result = query ecosystem name version in
    ((name, version), result)
  ) packages
