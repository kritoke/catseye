let default_db =
  let home = Sys.getenv "HOME" in
  home ^ "/.facet-pi/feedback.db"

let db = ref default_db

let columns = [|
  "id"; "timestamp"; "file_path"; "code_snippet";
  "detection_type"; "tool_name"; "issue_description"; "user_notes"
|]

let spec_list =
  [ ("-d", Arg.Set_string db, " Database path (default: $HOME/.facet-pi/feedback.db)") ;
    ("--db", Arg.Set_string db, " Database path") ]

let usage = "catseye-feedback [command] [options]\n\n\
  Read commands: summary (default), scans, fp, missed, new, json [type]\n\
  Write commands: import [file]   (reads catseye JSON from file or stdin)"

let data_to_string = function
  | Sqlite3.Data.TEXT s -> s
  | Sqlite3.Data.INT n -> Int64.to_string n
  | Sqlite3.Data.FLOAT f -> string_of_float f
  | Sqlite3.Data.NULL -> ""
  | Sqlite3.Data.BLOB b -> b
  | Sqlite3.Data.NONE -> ""

(* ── Read-only connection ────────────────────────────────────── *)

let with_db f =
  let db_path = !db in
  if not (Sys.file_exists db_path) then begin
    Printf.eprintf "No feedback database at %s\n" db_path;
    exit 1
  end;
  let db = Sqlite3.db_open ~mode:`READONLY db_path in
  Fun.protect
    ~finally:(fun () -> ignore (Sqlite3.db_close db))
    (fun () -> f db)

(* ── Read-write connection (creates DB if missing) ───────────── *)

let create_table_sql =
  "CREATE TABLE IF NOT EXISTS feedback (\
   \n  id INTEGER PRIMARY KEY AUTOINCREMENT,\
   \n  timestamp TEXT NOT NULL DEFAULT (datetime('now')),\
   \n  file_path TEXT,\
   \n  code_snippet TEXT,\
   \n  detection_type TEXT NOT NULL,\
   \n  tool_name TEXT NOT NULL,\
   \n  issue_description TEXT,\
   \n  user_notes TEXT)"

let with_db_write f =
  let db_path = !db in
  ignore (Sys.command ("mkdir -p " ^ Filename.dirname db_path));
  let db = Sqlite3.db_open db_path in
  let stmt = Sqlite3.prepare db create_table_sql in
  ignore (Sqlite3.step stmt);
  ignore (Sqlite3.finalize stmt);
  Fun.protect
    ~finally:(fun () -> ignore (Sqlite3.db_close db))
    (fun () -> f db)

(* ── Query helpers ───────────────────────────────────────────── *)

let query db sql params =
  let stmt = Sqlite3.prepare db sql in
  List.iteri (fun i p -> Sqlite3.bind stmt (i + 1) p |> ignore) params;
  let rec collect rows =
    match Sqlite3.step stmt with
    | Sqlite3.Rc.ROW ->
      let n = Sqlite3.column_count stmt in
      let row = Array.init n (fun i -> data_to_string (Sqlite3.column stmt i)) in
      collect (row :: rows)
    | Sqlite3.Rc.DONE -> List.rev rows
    | rc ->
      Printf.eprintf "Query error: %s\n" (Sqlite3.Rc.to_string rc);
      List.rev rows
  in
  let rows = collect [] in
  ignore (Sqlite3.finalize stmt);
  rows

let exec db sql params =
  let stmt = Sqlite3.prepare db sql in
  List.iteri (fun i p -> Sqlite3.bind stmt (i + 1) p |> ignore) params;
  ignore (Sqlite3.step stmt);
  ignore (Sqlite3.finalize stmt)

(* ── Read commands ───────────────────────────────────────────── *)

let show_summary db =
  let rows = query db "SELECT detection_type, COUNT(*) FROM feedback GROUP BY detection_type ORDER BY COUNT(*) DESC" [] in
  List.iter (fun row ->
    Printf.printf "%-20s %s\n" row.(0) row.(1)
  ) rows

let show_scans db =
  let rows = query db "SELECT id, tool_name, file_path, issue_description, user_notes FROM feedback WHERE detection_type = 'scan_result' ORDER BY id DESC LIMIT 50" [] in
  Printf.printf "%4s  %-12s  %-41s  %-61s  Notes\n" "ID" "Tool" "File" "Description";
  Printf.printf "%s\n" (String.make 160 '-');
  let trunc s len = if String.length s > len then String.sub s 0 len else s in
  List.iter (fun row ->
    Printf.printf "%4s  %-12s  %-41s  %-61s  %s\n"
      row.(0)
      (trunc row.(1) 12)
      (trunc row.(2) 40)
      (trunc row.(3) 60)
      row.(4)
  ) rows

let show_by_type db dtype =
  let rows = query db "SELECT id, tool_name, file_path, issue_description, user_notes FROM feedback WHERE detection_type = ? ORDER BY id DESC" [ Sqlite3.Data.TEXT dtype ] in
  List.iter (fun row ->
    Printf.printf "#%s [%s] %s\n  %s\n  Notes: %s\n\n" row.(0) row.(1) row.(2) row.(3) row.(4)
  ) rows

let show_json db dtype =
  let (sql, params) = match dtype with
    | "" -> ("SELECT * FROM feedback ORDER BY id DESC", [])
    | t -> ("SELECT * FROM feedback WHERE detection_type = ? ORDER BY id DESC", [ Sqlite3.Data.TEXT t ])
  in
  let rows = query db sql params in
  let maps = List.map (fun row ->
    Array.mapi (fun i v ->
      let col = columns.(i) in
      (col, `String v)
    ) row
    |> Array.to_list
    |> fun pairs -> `Assoc pairs
  ) rows in
  let json = `List maps in
  Printf.printf "%s\n" (Yojson.Basic.pretty_to_string json)

(* ── Import command ──────────────────────────────────────────── *)

let get_field obj field default =
  match Yojson.Basic.Util.member field obj with
  | `String s -> s
  | `Int n -> Int.to_string n
  | `Float f -> string_of_float f
  | _ -> default

let import_finding db cwd (finding : Yojson.Basic.t) =
  let file = get_field finding "file" "" in
  (* Make path relative to cwd if absolute *)
  let file_path =
    if cwd <> "" && String.length file > String.length cwd && String.sub file 0 (String.length cwd) = cwd then
      let rest = String.sub file (String.length cwd) (String.length file - String.length cwd) in
      let len = String.length rest in
      let start = ref 0 in
      while !start < len && String.get rest !start = '/' do incr start done;
      String.sub rest !start (len - !start)
    else
      file
  in
  let tool = get_field finding "tool" "catseye" in
  let rule = get_field finding "rule" "unknown" in
  let severity = get_field finding "severity" "unknown" in
  let message = get_field finding "message" "" in
  let line = get_field finding "line" "" in
  let issue_desc = Printf.sprintf "%s: %s" rule message in
  let notes = Printf.sprintf "severity=%s, line=%s" severity line in
  let sql = "INSERT INTO feedback (file_path, detection_type, tool_name, issue_description, user_notes) VALUES (?, 'scan_result', ?, ?, ?)" in
  exec db sql [ Sqlite3.Data.TEXT file_path; Sqlite3.Data.TEXT tool; Sqlite3.Data.TEXT issue_desc; Sqlite3.Data.TEXT notes ]

let import_json db json_str cwd =
  let json = Yojson.Basic.from_string json_str in
  let findings =
    match json with
    | `Assoc props ->
      (* Catseye output: {"findings": [...], ...} *)
      (match Yojson.Basic.Util.to_option Yojson.Basic.Util.to_list (Yojson.Basic.Util.member "findings" (`Assoc props)) with
       | Some items -> items
       | None ->
         (* Single finding as object *)
         [ json ])
    | `List items -> items
    | _ -> []
  in
  List.iter (import_finding db cwd) findings;
  Printf.printf "Imported %d findings\n" (List.length findings)

let rec do_import args =
  let (input, cwd) = match args with
    | [] ->
      (* Read from stdin *)
      (read_all Stdlib.stdin, Sys.getcwd ())
    | filename :: _ ->
      (* Read from file; cwd = parent dir of scanned project *)
      let ch = open_in filename in
      let len = in_channel_length ch in
      let buf = Bytes.create len in
      really_input ch buf 0 len;
      close_in ch;
      (Bytes.to_string buf, Sys.getcwd ())
  in
  with_db_write (fun db -> import_json db input cwd)

and read_all ic =
  let buf = Buffer.create 8192 in
  let tmp = Bytes.create 4096 in
  let rec loop () =
    let n = input ic tmp 0 4096 in
    if n = 0 then Buffer.contents buf
    else begin
      Buffer.add_subbytes buf tmp 0 n;
      loop ()
    end
  in
  loop ()

(* ── Main ────────────────────────────────────────────────────── *)

let () =
  let args = ref [] in
  Arg.parse spec_list (fun a -> args := !args @ [a]) usage;
  let all_args = !args in
  let cmd = ref "summary" in
  let filter = ref "" in
  let import_args = ref [] in
  (match List.nth_opt all_args 0 with
   | Some "summary" -> cmd := "summary"
   | Some "scans" -> cmd := "scans"
   | Some "fp" -> cmd := "fp"
   | Some "missed" -> cmd := "missed"
   | Some "new" -> cmd := "new"
   | Some "json" ->
     cmd := "json";
     (match List.nth_opt all_args 1 with
      | Some t -> filter := t
      | None -> ())
   | Some "import" ->
     cmd := "import";
     import_args := List.tl all_args
   | Some unknown ->
     Printf.eprintf "Unknown command: %s\nAvailable: summary, scans, fp, missed, new, json [type], import [file]\n" unknown;
     exit 1
   | None -> ());

  match !cmd with
  | "import" -> do_import !import_args
  | _ -> with_db (fun db ->
    match !cmd with
    | "summary" -> show_summary db
    | "scans" -> show_scans db
    | "fp" -> show_by_type db "false_positive"
    | "missed" -> show_by_type db "missed_issue"
    | "new" -> show_by_type db "new_finding"
    | "json" -> show_json db !filter
    | _ -> show_summary db
  )
