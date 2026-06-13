(* lib/catseye_claws/dry.ml *)

(** DRY violation detector via structural hashing.

    Algorithm:
    1. SLICE   — create overlapping windows of N consecutive nodes per file
    2. NORMALIZE — produce canonical string (strip var names, preserve call names)
    3. HASH    — hash normalized string
    4. BUCKET  — group windows by hash
    5. REPORT  — buckets with >= 2 unique locations are violations

    This detects copy-paste-with-rename, the most common form of duplication.
*)

open Base

(* String comparison shadows - Base remaps = and <>, use Stdlib explicitly *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_types

(* ── Window type ────────────────────────────────────────────────────── *)

type window = {
  file : string;
  start_line : int;
  end_line : int;
  hash : string;
}

(* ── Normalization ──────────────────────────────────────────────────── *)

(** Produce a canonical string for a single Security_node.

    Call names are preserved (API patterns matter for duplication).
    Variable names are stripped (catches copy-paste-with-rename).
    Instance-var assigns (@x = x) are normalized to a special marker
    that is excluded from DRY windows — they're Crystal constructor boilerplate,
    not meaningful duplication.
*)
let normalize_node (n : Security_node.t) : string =
  let arg_count = Stdlib.List.length n.args in
  match n.Security_node.node_type with
  | Security_node.Call ->
    (* Check if any arg looks like a SQL statement — if so, include the
       literal value to prevent different SQL statements from hashing the same.
       SQL statements are inherently repetitive (UPDATE ... SET ... WHERE ...)
       but semantically distinct when operating on different columns. *)
    let has_sql_arg = Stdlib.List.exists (fun (a : Security_node.arg) ->
      let v = Stdlib.String.lowercase_ascii a.Security_node.value in
      Stdlib.String.length v >= 6 &&
      (Stdlib.List.mem (Stdlib.String.sub v 0 6) ["select"; "insert"; "update"; "delete"; "create"])
    ) n.args in
    if has_sql_arg then
      (* Include enough of the SQL to differentiate statements *)
      let sql_arg = try
        Stdlib.List.find (fun (a : Security_node.arg) ->
          let v = Stdlib.String.lowercase_ascii a.Security_node.value in
          Stdlib.String.length v >= 6 &&
          (Stdlib.List.mem (Stdlib.String.sub v 0 6) ["select"; "insert"; "update"; "delete"; "create"])
        ) n.args
      with Stdlib.Not_found -> failwith "internal: sql arg not found"
      in
      (* Hash the full SQL string to make each unique statement its own bucket *)
      let sql_hash = Stdlib.Hashtbl.hash sql_arg.Security_node.value in
      Stdlib.Printf.sprintf "Call|%s|%08x" n.Security_node.name sql_hash
    else
      Stdlib.Printf.sprintf "Call|%s|%d" n.Security_node.name arg_count
  | Security_node.Assign ->
    (* Instance var assigns (@x = x) are constructor boilerplate *)
    if Stdlib.String.length n.Security_node.name > 0 && Stdlib.String.get n.Security_node.name 0 = '@' then
      "Assign|@inst|1"
    else
      Stdlib.Printf.sprintf "Assign|_|%d" arg_count
  | Security_node.Def ->
    Stdlib.Printf.sprintf "Def|_|%d" arg_count
  | Security_node.Var ->
    "Var|_|0"
  | Security_node.Literal ->
    "Literal|_|0"
  | Security_node.Import ->
    "Import|_|0"
  | Security_node.Guard ->
    "Guard|_|0"
  | Security_node.Class ->
    "Class|_|0"
  | Security_node.Module ->
    "Module|_|0"
  | Security_node.Enum ->
    "Enum|_|0"
  | Security_node.Control ->
    "Control|_|0"
  | Security_node.Terminator ->
    "Terminator|_|0"
  | Security_node.IgnoredReturn ->
    Stdlib.Printf.sprintf "IgnoredReturn|%s|%d" n.Security_node.name arg_count
  | Security_node.NonAtomicFileOp ->
    Stdlib.Printf.sprintf "NonAtomicFileOp|%s|%d" n.Security_node.name arg_count
  | Security_node.UnboundedRead ->
    Stdlib.Printf.sprintf "UnboundedRead|%s|%d" n.Security_node.name arg_count
  | Security_node.TOCTOU ->
    Stdlib.Printf.sprintf "TOCTOU|%s|%d" n.Security_node.name arg_count

(** Normalize a window of nodes to a canonical string. *)
let normalize_window (nodes : Security_node.t list) : string =
  Stdlib.String.concat "|" (Stdlib.List.map normalize_node nodes)

(* ── Hashing ────────────────────────────────────────────────────────── *)

(** Structural hash of a normalized window.

    Uses OCaml's built-in Hashtbl.hash (polymorphic hash) and
    takes the lower 32 bits as hex. Good enough for bucketing.
*)
let structural_hash (normalized : string) : string =
  let h = Stdlib.Hashtbl.hash normalized in
  Stdlib.Printf.sprintf "%08x" (Stdlib.Int.logand h 0xFFFFFFFF)

(* ── Window generation ──────────────────────────────────────────────── *)

(** Check if all Call nodes in a window have the same name.
    This detects repetitive boilerplate like DB read patterns
    (rows.read, db.query) that are not meaningful duplication. *)
let is_boilerplate_window (nodes : Security_node.t list) : bool =
  let call_names = Stdlib.List.filter_map (fun (n : Security_node.t) ->
    if n.Security_node.node_type = Security_node.Call then
      Some n.Security_node.name
    else None
  ) nodes in
  match call_names with
  | [] | [_] -> false
  | first :: rest ->
    (* If all calls are the same, it's boilerplate *)
    Stdlib.List.for_all (fun name -> name = first) rest
    (* Also check if the boilerplate is a known Crystal DB/IO pattern *)
    && (let lower = Stdlib.String.lowercase_ascii first in
        Stdlib.List.exists (fun pat ->
          let plen = Stdlib.String.length pat in
          Stdlib.String.length lower >= plen && Stdlib.String.sub lower 0 plen = pat
        ) ["rows."; "db."; "io."; "file."; "dir."; "env."])

(** Generate overlapping windows from a sorted node list, filtering
    out boilerplate windows (repetitive DB read patterns). *)
let generate_windows (file : string) (nodes : Security_node.t list) (size : int)
    : window list =
  let arr = Stdlib.Array.of_list nodes in
  let n = Stdlib.Array.length arr in
  if n < size then []
  else begin
    let windows = Stdlib.ref [] in
    for i = 0 to n - size do
      let window_nodes = Stdlib.Array.sub arr i size |> Stdlib.Array.to_list in
      (* Skip boilerplate windows: all calls have the same name (DB read patterns) *)
      if is_boilerplate_window window_nodes then ()
      else begin
        let norm = normalize_window window_nodes in
        let hash = structural_hash norm in
        windows := {
          file;
          start_line = (Stdlib.Array.get arr i).Security_node.line;
          end_line = (Stdlib.Array.get arr (i + size - 1)).Security_node.line;
          hash;
        } :: !windows
      end
    done;
    Stdlib.List.rev !windows
  end

(* ── Grouping ───────────────────────────────────────────────────────── *)

(** Group nodes by file, filtering out Import/Guard nodes that are
    not meaningful for DRY detection (require statements, guards). *)
let group_by_file (nodes : Security_node.t list) : (string * Security_node.t list) list =
  let tbl = Stdlib.Hashtbl.create 16 in
  Stdlib.List.iter (fun (n : Security_node.t) ->
    (* Skip Import and Guard nodes — require statements and guards
       are not meaningful code duplication targets. Also skip Crystal
       macro-generated accessors (property, getter, setter, include)
       which are language constructs, not user code. *)
    let skip = match n.Security_node.node_type with
      | Security_node.Import | Security_node.Guard -> true
      | Security_node.Class | Security_node.Module | Security_node.Enum -> true
      | Security_node.Control | Security_node.Terminator -> true
      | Security_node.Call ->
        let name = n.Security_node.name in
        name = "property" || name = "getter" || name = "setter"
        || name = "class_property" || name = "class_getter" || name = "class_setter"
        || name = "include"
      | _ -> false
    in
    if skip then ()
    else begin
      let existing = try Stdlib.Hashtbl.find tbl n.Security_node.file with Stdlib.Not_found -> [] in
      Stdlib.Hashtbl.replace tbl n.Security_node.file (n :: existing)
    end
  ) nodes;
  Stdlib.Hashtbl.fold (fun file file_nodes acc ->
    let sorted = Stdlib.List.sort (fun a b -> Int.compare a.Security_node.line b.Security_node.line) file_nodes in
    (file, sorted) :: acc
  ) tbl []

(* ── Deduplication ──────────────────────────────────────────────────── *)

(** Remove windows at the same (file, start_line) location. *)
let unique_by_location (windows : window list) : window list =
  let seen = Stdlib.Hashtbl.create 16 in
  Stdlib.List.filter (fun (w : window) ->
    let key = Stdlib.Printf.sprintf "%s:%d" w.file w.start_line in
    if Stdlib.Hashtbl.mem seen key then false
    else begin Stdlib.Hashtbl.add seen key true; true end
  ) windows

(* ── Finding construction ───────────────────────────────────────────── *)

let make_dry_finding (windows : window list) : Finding.t =
  let count = Stdlib.List.length windows in
  let first = Stdlib.List.hd windows in
  let locations = Stdlib.List.map (fun (w : window) ->
    { Finding.file = w.file; line = w.start_line
    ; message = Stdlib.Printf.sprintf "Duplicate block (lines %d-%d)" w.start_line w.end_line
    }
  ) windows in
  { Finding.rule = "DRYViolation"
  ; severity = "Medium"
  ; file = first.file
  ; line = first.start_line
  ; message = Stdlib.Printf.sprintf
      "Duplicate code block found in %d location(s) (consider extracting shared logic)"
      count
  ; flow = locations
  ; language = ""
  ; dependency = None
  ; reachability = None
  ; suggestion = None
  }

(* ── Detection ──────────────────────────────────────────────────────── *)

(** File patterns that are exempt from DRY checks.
    Constants tables, benchmarks, and examples are inherently repetitive
    and flagging them adds noise, not signal. *)
let is_dry_exempt_file = Scope.is_dry_exempt_file

(** Detect DRY violations across all files. *)
let detect (nodes : Security_node.t list) (config : Types.claws_config)
    : Finding.t list =
  if not config.dry_enabled then []
  else begin
    let by_file = group_by_file nodes in
    let by_file = Stdlib.List.filter (fun (file, _) -> not (is_dry_exempt_file file)) by_file in
    (* Generate all windows *)
    let all_windows = Stdlib.List.concat_map (fun (_file, fnodes) ->
      generate_windows _file fnodes config.dry_window_size
    ) by_file in
    (* Bucket by hash *)
    let buckets : (string, window list) Stdlib.Hashtbl.t = Stdlib.Hashtbl.create 256 in
    Stdlib.List.iter (fun (w : window) ->
      let existing = try Stdlib.Hashtbl.find buckets w.hash with Stdlib.Not_found -> [] in
      Stdlib.Hashtbl.replace buckets w.hash (w :: existing)
    ) all_windows;
    (* Filter to violations: >= min_occurrences unique locations
       across at least 2 different files (same-file repetition is weaker signal). *)
    Stdlib.Hashtbl.fold (fun _hash (windows : window list) acc ->
      let unique = unique_by_location windows in
      let unique_files =
        Stdlib.List.fold_left (fun s (w : window) ->
          if Stdlib.List.mem w.file s then s else w.file :: s
        ) [] unique
      in
      if Stdlib.List.length unique >= config.dry_min_occurrences
         && Stdlib.List.length unique_files >= 2 then
        make_dry_finding unique :: acc
      else acc
    ) buckets []
  end