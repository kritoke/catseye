(* lib/catseye_cli/export_rules.ml *)
(* Export rules in AI-friendly JSON format for database population *)

open Base

(* ── Types ──────────────────────────────────────────────────────────── *)

type sink = {
  function_name : string;
  argument_index : int option;
  value_constraint : string option;
  sanitizers : string list;
  suggested_fix : string option;
}

type source = {
  name : string;
  field : string option;
}

type language_filter = {
  include_langs : string list option;
  exclude_langs : string list option;
}

type rule = {
  id : string;
  name : string;
  severity : string;
  description : string;
  sinks : sink list;
  sources : source list;
  message_template : string;
  languages : string list;
}

type ai_rules_output = {
  language : string;
  rules : rule list;
  generated_at : string;
  total_rules : int;
  total_sinks : int;
  total_sources : int;
}

(* ── KDL Parser ──────────────────────────────────────────────────────── *)

let trim s =
  let len = String.length s in
  let rec left i =
    if i >= len || s.[i] <> ' ' && s.[i] <> '\t' then i else left (i + 1)
  in
  let rec right i =
    if i <= 0 || s.[i - 1] <> ' ' && s.[i - 1] <> '\t' then i else right (i - 1)
  in
  let start = left 0 in
  let stop = right len in
  if start >= stop then "" else String.sub s start (stop - start)

let split_on_newline s =
  String.split s ~on:'\n'

let split_on_space s =
  String.split s ~on:' ' |> List.filter ~f:(fun x -> String.length x > 0)

let extract_rule_name line =
  let t = trim line in
  if String.is_prefix t ~prefix:"rule \"" then
    let rest = String.sub t ~pos:6 ~len:(String.length t - 7) in
    Some (trim rest)
  else None

let extract_severity block =
  let lines = split_on_newline block in
  List.find_map lines ~f:(fun line ->
    if String.is_prefix (trim line) ~prefix:"severity=" then
      let rest = String.sub (trim line) ~pos:8 ~len:(String.length (trim line) - 8) in
      let rest = trim rest in
      (* Remove quotes if present *)
      let rest = if String.length rest >= 2 && rest.[0] = '"' then
        String.sub rest ~pos:1 ~len:(String.length rest - 2) |> trim
      else rest in
      Some rest
    else None
  )

let extract_languages block =
  let lines = split_on_newline block in
  let includes = ref [] in
  let excludes = ref [] in
  let rec parse_lang_section in_langs in_excludes = function
    | [] -> ()
    | line :: rest ->
      let t = trim line in
      if t = "languages {" then
        parse_lang_section true false rest
      else if String.length t > 0 && t.[0] = '}' then
        ()
      else if String.is_prefix t ~prefix:"include \"" then
        let lang = String.sub t ~pos:8 ~len:(String.length t - 9) in
        includes := lang :: !includes;
        parse_lang_section in_langs in_excludes rest
      else if String.is_prefix t ~prefix:"exclude \"" then
        let lang = String.sub t ~pos:8 ~len:(String.length t - 9) in
        excludes := lang :: !excludes;
        parse_lang_section in_langs in_excludes rest
      else
        parse_lang_section in_langs in_excludes rest
  in
  parse_lang_section false false lines;
  ({ include_langs = if List.is_empty !includes then None else Some !includes;
     exclude_langs = if List.is_empty !excludes then None else Some !excludes },
   List.rev !includes)

let parse_arg_value s =
  if String.is_prefix s ~prefix:"arg=" then
    let num_str = String.sub s ~pos:4 ~len:(String.length s - 4) in
    (try Some (Int.of_string num_str) with _ -> None)
  else if String.is_prefix s ~prefix:"value=" then
    None  (* value constraints handled separately *)
  else None

let extract_sinks block =
  let lines = split_on_newline block in
  let sinks = ref [] in
  let current_sink = ref None in
  let current_sanitizers = ref [] in
  let current_fix = ref None in
  
  let flush_sink () =
    match !current_sink with
    | None -> ()
    | Some (fn, arg_idx) ->
      let sink = {
        function_name = fn;
        argument_index = arg_idx;
        value_constraint = None;
        sanitizers = List.rev !current_sanitizers;
        suggested_fix = !current_fix;
      } in
      sinks := sink :: !sinks
  in
  
  let rec parse_sinks_section = function
    | [] -> flush_sink ()
    | line :: rest ->
      let t = trim line in
      if t = "sinks {" then
        parse_sinks_section rest
      else if String.length t > 0 && t.[0] = '}' && !current_sink <> None then
        flush_sink ()
      else if String.is_prefix t ~prefix:"sink \"" then
        (* Flush previous sink if any *)
        flush_sink ();
        (* Parse new sink definition *)
        let rest_content = String.sub t ~pos:5 ~len:(String.length t - 5) in
        let parts = split_on_space rest_content in
        let fn, arg_idx, value =
          match parts with
          | [] -> ("", None, None)
          | p :: _ ->
            let fn_raw = String.sub p ~pos:1 ~len:(String.length p - 2) in
            let arg_idx = List.find_map parts ~f:(fun part ->
              if String.is_prefix part ~prefix:"arg=" then
                let num_str = String.sub part ~pos:4 ~len:(String.length part - 4) in
                try Some (Int.of_string num_str) with _ -> None
              else None
            ) |> List.hd in
            let value =
              List.find_map parts ~f:(fun part ->
                if String.is_prefix part ~prefix:"value=" then
                  Some (String.sub part ~pos:6 ~len:(String.length part - 6))
                else None
              ) |> List.hd
            in
            (fn_raw, arg_idx, value)
        in
        current_sink := Some (fn, arg_idx);
        current_sanitizers := [];
        current_fix := None;
        parse_sinks_section rest
      else if String.is_prefix t ~prefix:"sanitizer \"" then
        let san = String.sub t ~pos:11 ~len:(String.length t - 12) in
        current_sanitizers := san :: !current_sanitizers;
        parse_sinks_section rest
      else if String.is_prefix t ~prefix:"fix \"" then
        let fix_str = String.sub t ~pos:5 ~len:(String.length t - 5) in
        let fix_str = if String.length fix_str >= 2 && fix_str.[0] = '"' then
          String.sub fix_str ~pos:1 ~len:(String.length fix_str - 2)
        else fix_str in
        current_fix := Some (trim fix_str);
        parse_sinks_section rest
      else
        parse_sinks_section rest
  in
  parse_sinks_section lines;
  List.rev !sinks

let extract_sources block =
  let lines = split_on_newline block in
  let sources = ref [] in
  let rec parse_sources_section = function
    | [] -> ()
    | line :: rest ->
      let t = trim line in
      if t = "sources {" then
        parse_sources_section rest
      else if String.length t > 0 && t.[0] = '}' then
        ()
      else if String.is_prefix t ~prefix:"source \"" then
        let rest_content = String.sub t ~pos:7 ~len:(String.length t - 7) in
        let parts = split_on_space rest_content in
        let name, field =
          match parts with
          | [] -> ("", None)
          | p :: rest_parts ->
            let name_raw = String.sub p ~pos:0 ~len:(String.length p - 1) in
            let field = List.find_map rest_parts ~f:(fun part ->
              if String.is_prefix part ~prefix:"field=" then
                Some (String.sub part ~pos:6 ~len:(String.length part - 6))
              else None
            ) |> List.hd in
            (name_raw, field)
        in
        sources := { name; field } :: !sources;
        parse_sources_section rest
      else
        parse_sources_section rest
  in
  parse_sources_section lines;
  List.rev !sources

let extract_message block =
  let lines = split_on_newline block in
  List.find_map lines ~f:(fun line ->
    if String.is_prefix (trim line) ~prefix:"message " then
      let rest = trim line in
      let content = 
        if String.length rest >= 8 then String.sub rest ~pos:8 ~len:(String.length rest - 8)
        else ""
      in
      (* Remove quotes if present *)
      let content = if String.length content >= 2 && content.[0] = '"' then
        String.sub content ~pos:1 ~len:(String.length content - 2)
      else content in
      Some (trim content)
    else None
  )

let parse_rule_content (name : string) (content : string) : rule option =
  let severity = extract_severity content |> Option.value ~default:"Medium" in
  let (lang_filter, languages) = extract_languages content in
  let sinks = extract_sinks content in
  let sources = extract_sources content in
  let message = extract_message content |> Option.value ~default:"" in
  
  Some {
    id = name;
    name = String.map name ~f:(fun c -> if c = '-' then '_' else c);
    severity;
    description = Printf.sprintf "Security rule for %s" name;
    sinks;
    sources;
    message_template = message;
    languages;
  }

let parse_kdl_file (content : string) : rule list =
  let lines = split_on_newline content in
  let rules = ref [] in
  let current_rule = ref None in
  let current_block = ref "" in
  let brace_count = ref 0 in
  let in_rule = ref false in
  
  let flush_rule () =
    match !current_rule with
    | None -> ()
    | Some name ->
      let rule_opt = parse_rule_content name !current_block in
      rules := (Option.value rule_opt ~default:{ 
        id = name; name; severity = "Medium"; description = ""; 
        sinks = []; sources = []; message_template = ""; languages = [] 
      }) :: !rules;
      current_rule := None;
      current_block := "";
      brace_count := 0;
      in_rule := false
  in
  
  List.iter lines ~f:(fun line ->
    match extract_rule_name line with
    | Some name ->
      flush_rule ();
      current_rule := Some name;
      in_rule := true
    | None ->
      if !in_rule then
        current_block := !current_block ^ line ^ "\n";
        let bc = ref 0 in
        String.iter line ~f:(fun c ->
          if c = '{' then bc := !bc + 1;
          if c = '}' then bc := !bc - 1
        );
        if !bc < 0 then flush_rule ()
  );
  
  flush_rule ();
  List.rev !rules

let parse_kdl_files (dir : string) : rule list =
  if not (Sys.file_exists dir) then []
  else
    let files = 
      Array.to_list (Sys.readdir dir)
      |> List.filter ~f:(fun f -> String.is_suffix f ~suffix:".kdl")
      |> List.sort String.compare
    in
    List.concat_map files ~f:(fun f ->
      let path = Filename.concat dir f in
      try
        let content = In_channel.read_all path in
        parse_kdl_file content
      with _ -> []
    )

(* ── JSON Output ────────────────────────────────────────────────────── *)

let escape_json s =
  let buf = Buffer.create (String.length s * 2) in
  String.iter s ~f:(fun c ->
    match c with
    | '"' -> Buffer.add_string buf "\\\""
    | '\\' -> Buffer.add_string buf "\\\\"
    | '\n' -> Buffer.add_string buf "\\n"
    | '\r' -> Buffer.add_string buf "\\r"
    | '\t' -> Buffer.add_string buf "\\t"
    | _ -> Buffer.add_char buf c
  );
  Buffer.contents buf

let json_quote s = "\"" ^ escape_json s ^ "\""

let sink_to_json (s : sink) : string =
  let arg_str = match s.argument_index with
    | Some i -> ", \"argument_index\": " ^ string_of_int i
    | None -> ""
  in
  let val_str = match s.value_constraint with
    | Some v -> ", \"value_constraint\": " ^ json_quote v
    | None -> ""
  in
  let san_list = String.concat ~sep:", " (List.map s.sanitizers ~f:json_quote) in
  let fix_str = match s.suggested_fix with
    | Some f -> ", \"suggested_fix\": " ^ json_quote f
    | None -> ""
  in
  Printf.sprintf "{\"function_name\": %s%s%s, \"sanitizers\": [%s]%s}"
    (json_quote s.function_name) arg_str val_str san_list fix_str

let source_to_json (s : source) : string =
  let field_str = match s.field with
    | Some f -> ", \"field\": " ^ json_quote f
    | None -> ""
  in
  Printf.sprintf "{\"name\": %s%s}" (json_quote s.name) field_str

let rule_to_json (r : rule) : string =
  let sinks_json = String.concat ~sep:", " (List.map r.sinks ~f:sink_to_json) in
  let sources_json = String.concat ~sep:", " (List.map r.sources ~f:source_to_json) in
  let langs_json = String.concat ~sep:", " (List.map r.languages ~f:json_quote) in
  Printf.sprintf 
    "{\"id\": %s, \"name\": %s, \"severity\": %s, \"description\": %s, \"sinks\": [%s], \"sources\": [%s], \"languages\": [%s], \"message_template\": %s}"
    (json_quote r.id)
    (json_quote r.name)
    (json_quote r.severity)
    (json_quote r.description)
    sinks_json
    sources_json
    langs_json
    (json_quote r.message_template)

let output_to_json (output : ai_rules_output) : string =
  let rules_json = String.concat ~sep:",\n      " (List.map output.rules ~f:rule_to_json) in
  let timestamp = 
    let now = Unix.gettimeofday () in
    let tm = Unix.localtime now in
    Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d" 
      (1900 + tm.Unix.tm_year) (tm.Unix.tm_mon + 1) tm.Unix.tm_mday
      tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec
  in
  Printf.sprintf "{\n  \"language\": %s,\n  \"generated_at\": \"%s\",\n  \"total_rules\": %d,\n  \"total_sinks\": %d,\n  \"total_sources\": %d,\n  \"rules\": [\n      %s\n  ]\n}"
    (json_quote output.language)
    timestamp
    output.total_rules
    output.total_sinks
    output.total_sources
    rules_json

(* ── Filter by Language ─────────────────────────────────────────────── *)

let language_matches_rule (lang : string) (languages : string list) : bool =
  List.is_empty languages || 
  List.exists languages ~f:(fun l -> 
    String.lowercase l = String.lowercase lang ||
    (String.length l >= 4 && String.is_prefix (String.lowercase l) ~prefix:(String.lowercase lang))
  )

let filter_rules_by_language (rules : rule list) (lang : string) : rule list =
  List.filter rules ~f:(fun r ->
    List.exists r.languages ~f:(fun l ->
      String.lowercase l = String.lowercase lang ||
      String.is_suffix (String.lowercase l) ~suffix:(String.lowercase lang)
    )
  )

(* ── Main Export Function ───────────────────────────────────────────── *)

let export_rules (rules_dir : string) (lang : string) (out_path : string option) : unit =
  let all_rules = parse_kdl_files rules_dir in
  let filtered = filter_rules_by_language all_rules lang in
  
  let total_sinks = List.fold filtered ~init:0 ~f:(fun acc r -> acc + List.length r.sinks) in
  let total_sources = List.fold filtered ~init:0 ~f:(fun acc r -> acc + List.length r.sources) in
  
  let output = {
    language = lang;
    rules = filtered;
    generated_at = "";
    total_rules = List.length filtered;
    total_sinks;
    total_sources;
  } in
  
  let json = output_to_json output in
  
  match out_path with
  | Some path ->
    let oc = open_out path in
    output_string oc json;
    close_out oc;
    print_endline ("Exported " ^ string_of_int (List.length filtered) ^ " rules to " ^ path)
  | None ->
    print_endline json