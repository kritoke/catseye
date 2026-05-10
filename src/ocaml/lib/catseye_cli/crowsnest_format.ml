(* lib/catseye_cli/crowsnest_format.ml
   Terminal formatting for Crow's Nest supply chain audit results. *)

open Config
open Catseye_crowsnest.Aggregator

(* ANSI color codes *)
let bold = "\027[1m"
let red = "\027[31m"
let yellow = "\027[33m"
let green = "\027[32m"
let dim = "\027[2m"
let reset = "\027[0m"

let styled color config text =
  if config.color then color ^ text ^ reset else text

let level_icon = function
  | `Hiss -> "🐱⚡ Hiss "
  | `Meow -> "🐾 Meow  "
  | `Purr -> "✅ Purr "

let level_color = function
  | `Hiss -> red
  | `Meow -> yellow
  | `Purr -> green

let osv_summary = function
  | Catseye_crowsnest.Osv.No_known_cves -> "Active, no known CVEs"
  | Catseye_crowsnest.Osv.Vulnerabilities vulns ->
    let worst = List.hd vulns in
    Printf.sprintf "%s %s" worst.Catseye_crowsnest.Osv.id
      (if worst.Catseye_crowsnest.Osv.summary <> "" then
         let words = String.split_on_char ' ' worst.Catseye_crowsnest.Osv.summary in
         String.concat " " (List.filteri (fun i _ -> i < 6) words) ^
         (if List.length words > 6 then "..." else "")
       else "")
  | Catseye_crowsnest.Osv.Query_failed _ -> "Query failed (offline?)"

let staleness_summary = function
  | None -> ""
  | Some s ->
    match s.Catseye_crowsnest.Staleness.signals with
    | [] -> ""
    | [signal] -> signal
    | signals -> List.hd signals

(** Print the full Crow's Nest report to terminal. *)
let print_crows_nest (config : t) (results : dep_result list) : unit =
  Printf.printf "\n  🏴‍☠️ CROW'S NEST — Supply Chain Audit\n\n";

  (* Group by ecosystem *)
  let crystal_deps = List.filter (fun r -> r.ecosystem = "crystal-shards") results in
  let hex_deps = List.filter (fun r -> r.ecosystem = "hex") results in

  if crystal_deps <> [] then begin
    Printf.printf "  ┌─ Crystal Shards (%s) ─────────────────────────────\n"
      (List.hd crystal_deps).source_file;
    List.iter (fun r ->
      let icon = level_icon r.level in
      let c = level_color r.level in
      let version = match r.version with
        | Some v -> v | None -> "*"
      in
      let desc = match r.osv, r.staleness with
        | Catseye_crowsnest.Osv.Vulnerabilities _, _ -> osv_summary r.osv
        | _, Some s when s.Catseye_crowsnest.Staleness.signals <> [] -> staleness_summary (Some s)
        | Catseye_crowsnest.Osv.No_known_cves, None -> osv_summary r.osv
        | _ -> osv_summary r.osv
      in
      Printf.printf "  │  %s%-12s %-8s %s%s  %s\n"
        (styled c config icon)
        r.name version
        (styled (bold ^ c) config "")
        (styled dim config desc)
        (styled reset config "")
    ) crystal_deps;
    Printf.printf "  └───────────────────────────────────────────────────┘\n\n"
  end;

  if hex_deps <> [] then begin
    Printf.printf "  ┌─ Gleam Hex Packages (%s) ────────────────────────\n"
      (List.hd hex_deps).source_file;
    List.iter (fun r ->
      let icon = level_icon r.level in
      let c = level_color r.level in
      let version = match r.version with
        | Some v -> v | None -> "*"
      in
      let desc = match r.osv, r.staleness with
        | Catseye_crowsnest.Osv.Vulnerabilities _, _ -> osv_summary r.osv
        | _, Some s when s.Catseye_crowsnest.Staleness.signals <> [] -> staleness_summary (Some s)
        | Catseye_crowsnest.Osv.No_known_cves, None -> osv_summary r.osv
        | _ -> osv_summary r.osv
      in
      Printf.printf "  │  %s%-12s %-8s %s%s  %s\n"
        (styled c config icon)
        r.name version
        (styled (bold ^ c) config "")
        (styled dim config desc)
        (styled reset config "")
    ) hex_deps;
    Printf.printf "  └───────────────────────────────────────────────────┘\n\n"
  end;

  (* Summary line *)
  let hiss = List.length (List.filter (fun r -> r.level = `Hiss) results) in
  let meow = List.length (List.filter (fun r -> r.level = `Meow) results) in
  let purr = List.length (List.filter (fun r -> r.level = `Purr) results) in
  Printf.printf "  ────────────────────────────────────────\n";
  Printf.printf "  %d Hiss  •  %d Meow  •  %d Purr\n\n" hiss meow purr;

  (* Detailed findings for Hiss/Meow *)
  let notable = List.filter (fun r -> r.level <> `Purr) results in
  List.iter (fun r ->
    let c = level_color r.level in
    let version = match r.version with Some v -> v | None -> "*" in
    Printf.printf "  %s%s %s %s — %s%s\n"
      (styled c config (level_icon r.level))
      r.name version
      (styled (bold ^ c) config "")
      (osv_summary r.osv)
      (styled reset config "");
    (* Staleness signals *)
    (match r.staleness with
     | Some s ->
       List.iter (fun signal ->
         Printf.printf "     %s\n" signal
       ) s.Catseye_crowsnest.Staleness.signals
     | None -> ());
    (* CVE references *)
    (match r.osv with
     | Catseye_crowsnest.Osv.Vulnerabilities vulns ->
       List.iter (fun v ->
         List.iter (fun url ->
           Printf.printf "     %s\n" url
         ) (List.filteri (fun i _ -> i < 2) v.Catseye_crowsnest.Osv.references)
       ) vulns
     | _ -> ());
    Printf.printf "\n"
  ) notable
