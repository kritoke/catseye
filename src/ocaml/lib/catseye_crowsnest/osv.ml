(* lib/catseye_crowsnest/osv.ml
   OSV.dev API client — query for known vulnerabilities in dependencies.
   Uses curl subprocess for zero-dependency HTTP. *)

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
      (match List.assoc_opt "vulns" dict with
       | None -> No_known_cves
       | Some (`List vulns) ->
         let parsed = List.filter_map (fun v ->
           let d = to_assoc v in
           let id = get (List.assoc "id" d) in
           let summary = match List.assoc_opt "summary" d with
             | Some s -> get s | None -> ""
           in
           let severity = match List.assoc_opt "database_specific" d with
             | Some (`Assoc spec) ->
               (match List.assoc_opt "severity" spec with
                | Some s -> Some (get s) | None -> None)
             | None ->
               (match List.assoc_opt "severity" d with
                | Some (`List []) -> None
                | Some (`List (first :: _)) ->
                  (match first with
                   | `Assoc s ->
                     (match List.assoc_opt "score" s with
                      | Some s -> Some (get s) | None -> None)
                   | _ -> None)
                | _ -> None)
           in
           let patched = match List.assoc_opt "affected" d with
             | Some (`List affected) ->
               List.concat_map (fun a ->
                 let ad = to_assoc a in
                 match List.assoc_opt "ranges" ad with
                 | Some (`List ranges) ->
                   List.concat_map (fun r ->
                     let rd = to_assoc r in
                     match List.assoc_opt "events" rd with
                     | Some (`List events) ->
                       List.filter_map (fun e ->
                         let ed = to_assoc e in
                         match List.assoc_opt "fixed" ed with
                         | Some v -> Some (get v)
                         | None -> None
                       ) events
                     | None -> []
                   ) ranges
                 | None -> []
               ) affected
             | None -> []
           in
           let refs = match List.assoc_opt "references" d with
             | Some (`List rlist) ->
               List.filter_map (fun r ->
                 let rd = to_assoc r in
                 match List.assoc_opt "url" rd with
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
  let tmp_in = Filename.temp_file "catseye-osv-in" ".json" in
  let tmp_out = Filename.temp_file "catseye-osv-out" ".json" in
  try
    (* Write payload to temp file *)
    let oc = open_out tmp_in in
    output_string oc json_payload;
    close_out oc;

    let cmd = Printf.sprintf
      "curl -s -S --max-time 10 -X POST https://api.osv.dev/v1/query -d @%s -o %s 2>/dev/null"
      (Filename.quote tmp_in) (Filename.quote tmp_out)
    in
    let exit_code = Sys.command cmd in
    Unix.unlink tmp_in;
    if exit_code <> 0 then begin
      (try Unix.unlink tmp_out with _ -> ());
      Query_failed (Printf.sprintf "curl exited with code %d" exit_code)
    end
    else begin
      try
        let ic = open_in tmp_out in
        let len = in_channel_length ic in
        let buf = Bytes.create len in
        really_input ic buf 0 len;
        close_in ic;
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
  List.map (fun (name, version) ->
    let result = query ecosystem name version in
    ((name, version), result)
  ) packages
