(* lib/catseye_cli/heatmap.ml
   Predator Vision — terminal heatmap formatter.

   Groups findings by file, computes per-file reachability ratios,
   and renders a visual attack surface heatmap. *)

open Config
open Catseye_types
open Catseye_engine.Reachability

(* ANSI color codes *)
let bold = "\027[1m"
let red = "\027[31m"
let yellow = "\027[33m"
let green = "\027[32m"
let dim = "\027[2m"
let reset = "\027[0m"

let styled color config text =
  if config.color then color ^ text ^ reset else text

(* ── Heatmap bar ────────────────────────────────────────────────────── *)

(** Render a Unicode block bar showing ratio of live/total.
    20 chars wide. Filled portion is live, empty is dormant/safe. *)
let heatmap_bar (config : t) (live : int) (total : int) : string =
  if total = 0 then String.make 20 '\176'  (* ~ for empty *)
  else begin
    let width = 20 in
    let filled = min width (live * width / total) in
    let empty = width - filled in
    let bar =
      (String.make filled '#') ^ (String.make empty '-')
    in
    let filled_part = String.sub bar 0 filled in
    let empty_part = String.sub bar filled empty in
    styled red config filled_part
    ^ styled dim config empty_part
  end

(* ── Status icon ────────────────────────────────────────────────────── *)

let status_icon = function
  | `Live -> "🔴 LIVE   "
  | `Dormant -> "🟡 DORMANT"
  | `Safe -> "✅ SAFE   "

let status_color = function
  | `Live -> red
  | `Dormant -> yellow
  | `Safe -> green

(* ── Per-file grouping ──────────────────────────────────────────────── *)

type file_findings = {
  file : string;
  items : (Finding.t * reachability) list;
  live : int;
  dormant : int;
  safe : int;
  total : int;
}

let group_by_file (findings : Finding.t list) (reach : reachability list)
    : file_findings list =
  (* Pair findings with reachability *)
  let pairs = List.combine findings reach in
  (* Group by file *)
  let file_map = Hashtbl.create 16 in
  List.iter (fun (f, r) ->
    let file = f.Finding.file in
    let current = try Hashtbl.find file_map file with Not_found -> [] in
    Hashtbl.replace file_map file ((f, r) :: current)
  ) pairs;
  (* Build file_findings records *)
  let results = ref [] in
  Hashtbl.iter (fun file items ->
    let live = List.length (List.filter (fun (_, r) -> r.status = `Live) items) in
    let dormant = List.length (List.filter (fun (_, r) -> r.status = `Dormant) items) in
    let safe = List.length (List.filter (fun (_, r) -> r.status = `Safe) items) in
    results := {
      file;
      items = List.sort (fun (a, _) (b, _) ->
        compare a.Finding.line b.Finding.line
      ) items;
      live; dormant; safe; total = live + dormant + safe;
    } :: !results
  ) file_map;
  (* Sort files by live count descending, then by name *)
  List.sort (fun a b ->
    let cmp_live = compare b.live a.live in
    if cmp_live <> 0 then cmp_live
    else String.compare a.file b.file
  ) !results

(* ── Terminal rendering ─────────────────────────────────────────────── *)

let print_heatmap (config : t)
    (findings : Finding.t list)
    (reach : reachability list) : unit =
  if findings = [] then ();
  let groups = group_by_file findings reach in
  let total_live = ref 0 in
  let total_dormant = ref 0 in
  let total_safe = ref 0 in

  Printf.printf "\n  🔴 PREDATOR VISION — Attack Surface Heatmap\n\n";

  List.iter (fun g ->
    let bar = heatmap_bar config g.live g.total in
    Printf.printf "  %s\n" (styled (bold) config g.file);
    Printf.printf "    %s  %d/%d sinks reachable\n"
      bar g.live g.total;

    List.iter (fun (f, r) ->
      let icon = status_icon r.status in
      let c = status_color r.status in
      Printf.printf "    ├── %s%s [%s]  :%d   %s%s\n"
        (styled c config icon)
        (styled (bold ^ c) config f.Finding.rule)
        f.Finding.rule
        f.Finding.line
        f.Finding.message
        reset;
      (* Show reachability path for Live findings *)
      if r.status = `Live && r.path <> [] then begin
        let path_str = String.concat " → "
          (List.map (fun (pf, pl) ->
            Printf.sprintf "%s:%d" (Filename.basename pf) pl
          ) r.path)
        in
        Printf.printf "    │    ↑ Reachable via: %s%s%s\n"
          (styled dim config "") path_str (styled reset config "")
      end;
      if r.status = `Dormant then
        Printf.printf "    │    ↑ Sink exists but not reachable from entry points\n"
    ) g.items;

    total_live := !total_live + g.live;
    total_dormant := !total_dormant + g.dormant;
    total_safe := !total_safe + g.safe;
    Printf.printf "\n"
  ) groups;

  Printf.printf "  ────────────────────────────────────────\n";
  Printf.printf "  %d LIVE PREY  •  %d DORMANT  •  %d SAFE\n"
    !total_live !total_dormant !total_safe;
  let total = !total_live + !total_dormant + !total_safe in
  if total > 0 then
    Printf.printf "  %d%% of sinks are reachable from entry points\n"
      (!total_live * 100 / total)
