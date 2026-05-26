(* lib/catseye_cli/crowsnest_format.ml
   Terminal formatting for Crow's Nest supply chain audit results. *)

open Base

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
  | `Critical -> "🔴 Critical "
  | `Warning -> "⚠️  Warning "
  | `Clean -> "✅ Clean    "

let level_color = function
  | `Critical -> red
  | `Warning -> yellow
  | `Clean -> green

let osv_summary = function
  | Catseye_crowsnest.Osv.No_known_cves -> "Active, no known CVEs"
  | Catseye_crowsnest.Osv.Vulnerabilities vulns ->
    (match vulns with
    | [] -> "Vulnerabilities found"
    | worst :: _ ->
      Stdlib.Printf.sprintf "%s %s" worst.Catseye_crowsnest.Osv.id
        (if worst.Catseye_crowsnest.Osv.summary <> "" then
           let words = Stdlib.String.split_on_char ' ' worst.Catseye_crowsnest.Osv.summary in
           Stdlib.String.concat " " (List.filteri ~f:(fun i _ -> i < 6) words) ^
           (if List.length words > 6 then "..." else "")
         else ""))
  | Catseye_crowsnest.Osv.Query_failed _ -> "Query failed (offline?)"

let staleness_summary = function
  | None -> ""
  | Some s ->
    match s.Catseye_crowsnest.Staleness.signals with
    | [] -> ""
    | [signal] -> signal
    | signals -> (match signals with s :: _ -> s | [] -> "")

(** Print the full Crow's Nest report to terminal. *)
let print_crows_nest (config : t) (results : dep_result list) : unit =
  Stdlib.Printf.printf "\n  🏴‍☠️ CROW'S NEST — Supply Chain Audit\n\n";

  (* Group by ecosystem *)
  let crystal_deps = List.filter ~f:(fun r -> r.ecosystem = "crystal-shards") results in
  let hex_deps = List.filter ~f:(fun r -> r.ecosystem = "hex") results in

  if crystal_deps <> [] then begin
    Stdlib.Printf.printf "  ┌─ Crystal Shards (%s) ─────────────────────────────\n"
      (match crystal_deps with dep :: _ -> dep.source_file | [] -> "");
    List.iter ~f:(fun r ->
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
      Stdlib.Printf.printf "  │  %s%-12s %-8s %s%s  %s\n"
        (styled c config icon)
        r.name version
        (styled (bold ^ c) config "")
        (styled dim config desc)
        (styled reset config "")
    ) crystal_deps;
    Stdlib.Printf.printf "  └───────────────────────────────────────────────────┘\n\n"
  end;

  if hex_deps <> [] then begin
    Stdlib.Printf.printf "  ┌─ Gleam Hex Packages (%s) ────────────────────────\n"
      (match hex_deps with dep :: _ -> dep.source_file | [] -> "");
    List.iter ~f:(fun r ->
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
      Stdlib.Printf.printf "  │  %s%-12s %-8s %s%s  %s\n"
        (styled c config icon)
        r.name version
        (styled (bold ^ c) config "")
        (styled dim config desc)
        (styled reset config "")
    ) hex_deps;
    Stdlib.Printf.printf "  └───────────────────────────────────────────────────┘\n\n"
  end;

  (* Summary line *)
  let critical = List.length (List.filter ~f:(fun r -> r.level = `Critical) results) in
  let warning = List.length (List.filter ~f:(fun r -> r.level = `Warning) results) in
  let clean = List.length (List.filter ~f:(fun r -> r.level = `Clean) results) in
  Stdlib.Printf.printf "  ────────────────────────────────────────\n";
  Stdlib.Printf.printf "  %d Critical  •  %d Warning  •  %d Clean\n\n" critical warning clean;

  (* Detailed findings for Critical/Warning *)
  let notable = List.filter ~f:(fun r -> r.level <> `Clean) results in
  List.iter ~f:(fun r ->
    let c = level_color r.level in
    let version = match r.version with Some v -> v | None -> "*" in
    Stdlib.Printf.printf "  %s%s %s %s — %s%s\n"
      (styled c config (level_icon r.level))
      r.name version
      (styled (bold ^ c) config "")
      (osv_summary r.osv)
(styled reset config "");
    (* Staleness signals *)
    (match r.staleness with
     | Some s ->
       List.iter ~f:(fun signal ->
         Stdlib.Printf.printf "     %s\n" signal
       ) s.Catseye_crowsnest.Staleness.signals
     | None -> ());
    (* CVE references *)
    (match r.osv with
     | Catseye_crowsnest.Osv.Vulnerabilities vulns ->
       List.iter ~f:(fun v ->
         List.iter ~f:(fun url ->
           Stdlib.Printf.printf "     %s\n" url
         ) (List.filteri ~f:(fun i _ -> i < 2) v.Catseye_crowsnest.Osv.references)
       ) vulns
     | _ -> ());
    Stdlib.Printf.printf "\n"
  ) notable
