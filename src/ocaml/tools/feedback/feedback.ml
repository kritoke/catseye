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

let usage = "catseye-feedback [command] [options]\n\nCommands: summary (default), scans, fp, missed, new, json [type]"

let data_to_string = function
  | Sqlite3.Data.TEXT s -> s
  | Sqlite3.Data.INT n -> Int64.to_string n
  | Sqlite3.Data.FLOAT f -> string_of_float f
  | Sqlite3.Data.NULL -> ""
  | Sqlite3.Data.BLOB b -> b
  | Sqlite3.Data.NONE -> ""

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

let () =
  let args = ref [] in
  Arg.parse spec_list (fun a -> args := !args @ [a]) usage;
  let all_args = !args in
  let cmd = ref "summary" in
  let filter = ref "" in
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
   | Some unknown ->
     Printf.eprintf "Unknown command: %s\nAvailable: summary, scans, fp, missed, new, json [type]\n" unknown;
     exit 1
   | None -> ());

  with_db (fun db ->
    match !cmd with
    | "summary" -> show_summary db
    | "scans" -> show_scans db
    | "fp" -> show_by_type db "false_positive"
    | "missed" -> show_by_type db "missed_issue"
    | "new" -> show_by_type db "new_finding"
    | "json" -> show_json db !filter
    | _ -> show_summary db
  )
