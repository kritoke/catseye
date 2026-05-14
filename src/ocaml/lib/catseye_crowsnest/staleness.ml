(* lib/catseye_crowsnest/staleness.ml
   Staleness detection — composite scoring for abandoned/end-of-life packages.
   Uses GitHub API (commits, releases, issues) and Hex API for Gleam packages. *)

type repo_activity = {
  last_commit_date : float option;
  last_release_date : float option;
  open_issues : int option;
  open_prs : int option;
}

type hex_package_info = {
  name : string;
  retired : [ `Active | `Retired of string | `Unknown ];
  last_release : float option;
}

type staleness = {
  score : int;
  signals : string list;
  level : [ `Clean | `Warning | `Critical ];
}

type months = float

(** Current time as Unix timestamp *)
let now () = Unix.time ()

(** Convert Unix timestamp to approximate months ago *)
let months_ago (ts : float) : months =
  (now () -. ts) /. (86400.0 *. 30.0)

(* ── GitHub API ─────────────────────────────────────────────────────── *)

let query_github (repo : string) : repo_activity option =
  (* repo is "user/repo" *)
  let tmp = Filename.temp_file "catseye-github" ".json" in
  let cmd = Printf.sprintf
    "curl -s -S --max-time 10 -H 'Accept: application/vnd.github+json' \
     'https://api.github.com/repos/%s' -o %s 2>/dev/null"
    (Filename.quote repo) (Filename.quote tmp)
  in
  let _ = Sys.command cmd in
  try
    let ic = open_in tmp in
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    really_input ic buf 0 len;
    close_in ic;
    Unix.unlink tmp;
    let json = Yojson.Safe.from_string (Bytes.to_string buf) in
    let get = Yojson.Safe.Util.to_string in
    let int_val = Yojson.Safe.Util.to_int in
    let to_assoc = Yojson.Safe.Util.to_assoc in
    let d = to_assoc json in
    let push_date = match List.assoc_opt "pushed_at" d with
      | Some v -> (try
        let s = get v in
        let ys = String.sub s 0 4 in
        let ms = String.sub s 5 2 in
        let ds = String.sub s 8 2 in
        let year = int_of_string ys in
        let month = int_of_string ms in
        let day = int_of_string ds in
        Some (Unix.mktime { Unix.tm_year = year - 1900; tm_mon = month - 1; tm_mday = day;
          tm_hour = 0; tm_min = 0; tm_sec = 0; tm_wday = 0; tm_yday = 0; tm_isdst = false } |> fst)
        with _ -> None)
      | None -> None
    in
    let issues = match List.assoc_opt "open_issues_count" d with
      | Some v -> (try Some (int_val v) with _ -> None)
      | None -> None
    in
    Some {
      last_commit_date = push_date;
      last_release_date = None;  (* Would need /releases endpoint *)
      open_issues = issues;
      open_prs = None;           (* Would need /pulls endpoint *)
    }
  with _ ->
    (try Unix.unlink tmp with _ -> ());
    None

(* ── Hex API ────────────────────────────────────────────────────────── *)

let query_hex (package : string) : hex_package_info option =
  let tmp = Filename.temp_file "catseye-hex" ".json" in
  let cmd = Printf.sprintf
    "curl -s -S --max-time 10 'https://hex.pm/api/packages/%s' -o %s 2>/dev/null"
    (Filename.quote package) (Filename.quote tmp)
  in
  let _ = Sys.command cmd in
  try
    let ic = open_in tmp in
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    really_input ic buf 0 len;
    close_in ic;
    Unix.unlink tmp;
    let json = Yojson.Safe.from_string (Bytes.to_string buf) in
    let get = Yojson.Safe.Util.to_string in
    let to_assoc = Yojson.Safe.Util.to_assoc in
    let d = to_assoc json in
    let retired = match List.assoc_opt "retirement" d with
      | Some (`Assoc r) ->
        (match List.assoc_opt "status" r with
         | Some (`String "retired") ->
           (match List.assoc_opt "message" r with
            | Some (`String m) -> `Retired m
            | None -> `Retired "retired")
         | _ -> `Active)
      | _ -> `Unknown
    in
    let last_release = match List.assoc_opt "latest_version" d with
      | Some (`Assoc v) ->
        (match List.assoc_opt "inserted_at" v with
         | Some (`String s) ->
           (try
             let ys = String.sub s 0 4 in
             let ms = String.sub s 5 2 in
             let ds = String.sub s 8 2 in
             let year = int_of_string ys in
             let month = int_of_string ms in
             let day = int_of_string ds in
             Some (Unix.mktime { Unix.tm_year = year - 1900; tm_mon = month - 1; tm_mday = day;
               tm_hour = 0; tm_min = 0; tm_sec = 0; tm_wday = 0; tm_yday = 0; tm_isdst = false } |> fst)
           with _ -> None)
         | _ -> None)
      | _ -> None
    in
    Some { name = package; retired; last_release }
  with _ ->
    (try Unix.unlink tmp with _ -> ());
    None

(* ── Composite staleness score ──────────────────────────────────────── *)

let compute_staleness ?repo ?hex ?(threshold_months = 12.0) () : staleness =
  let score = ref 0 in
  let signals = ref [] in

  (* GitHub signals *)
  (match repo with
   | Some r ->
     (* Last commit staleness *)
     (match r.last_commit_date with
      | Some ts ->
        let months = months_ago ts in
        if months > 12.0 then begin
          score := !score + 2;
          signals := Printf.sprintf "No commits in %.0f months" months :: !signals
        end
        else if months > 6.0 then begin
          score := !score + 1;
          signals := Printf.sprintf "Last commit %.0f months ago" months :: !signals
        end
      | None -> ());
     (* Last release staleness *)
     (match r.last_release_date with
      | Some ts ->
        let months = months_ago ts in
        if months > threshold_months then begin
          score := !score + 3;
          signals := Printf.sprintf "No release in %.0f months" months :: !signals
        end
      | None -> ());
     (* Open issues count *)
     (match r.open_issues with
      | Some n when n > 50 ->
        score := !score + 1;
        signals := Printf.sprintf "%d open issues" n :: !signals
      | _ -> ());
     (* Open PRs count *)
     (match r.open_prs with
      | Some n when n > 10 ->
        score := !score + 1;
        signals := Printf.sprintf "%d open PRs" n :: !signals
      | _ -> ())
   | None -> ());

  (* Hex signals *)
  (match hex with
   | Some h ->
     (match h.retired with
      | `Retired msg ->
        score := !score + 5;
        signals := Printf.sprintf "Package retired: %s" msg :: !signals
      | `Active -> ()
      | `Unknown -> ());
     (match h.last_release with
      | Some ts ->
        let months = months_ago ts in
        if months > threshold_months then begin
          score := !score + 3;
          signals := Printf.sprintf "Last Hex release %.0f months ago" months :: !signals
        end
      | None -> ())
   | None -> ());

  let level = match !score with
    | n when n >= 6 -> `Critical
    | n when n >= 3 -> `Warning
    | _ -> `Clean
  in
  { score = !score; signals = List.rev !signals; level }
