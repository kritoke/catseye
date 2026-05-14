import re

with open('lib/catseye_ast/gleam_mapper.ml', 'r') as f:
    content = f.read()

# Find the parse_file function and replace the parse call
old_code = '''let parse_file ~(path : string) : (t, parse_error) result =
  let grammar_path = try Some (Sys.getenv "TREE_SITTER_GLEAM_GRAMMAR") with Not_found -> None in
  match grammar_path with
  | None ->
      Error (make_error ~file:path ~message:"TREE_SITTER_GLEAM_GRAMMAR not set")
  | Some grammar ->
      let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name gleam -x '%s' 2>/dev/null" grammar path in
      let ic = Unix.open_process_in cmd in
      let xml_str = Buffer.create 4096 in
      (try while true do Buffer.add_channel xml_str ic 4096 done with End_of_file -> ());
      let status = Unix.close_process_in ic in
      match status with
      | Unix.WEXITED 0 ->
          let xml = parse_xml (Buffer.contents xml_str) in
          let items = List.filter (fun c -> List.mem c.tag ["function"; "import"; "type"]) xml.children in
          Ok { mod_lang = Gleam; mod_path = path; mod_items = List.map item_of_xml items; parse_errors = [] }
      | _ ->
          Error (make_error ~file:path ~message:"tree-sitter parse failed")'''

new_code = '''let parse_file ~(path : string) : (t, parse_error) result =
  let grammar_path = try Some (Sys.getenv "TREE_SITTER_GLEAM_GRAMMAR") with Not_found -> None in
  match grammar_path with
  | None ->
      Error (make_error ~file:path ~message:"TREE_SITTER_GLEAM_GRAMMAR not set")
  | Some grammar ->
      let lib_path = grammar ^ "/gleam.so" in
      let cmd = Printf.sprintf "tree-sitter parse --lib-path '%s' --lang-name gleam -x '%s' 2>&1" lib_path path in
      let env = Array.append (Unix.environment ()) [| "LD_LIBRARY_PATH=" ^ grammar |] in
      (try
        let (ic, oc, ec) = Unix.open_process_full cmd env in
        let xml_str = Buffer.create 4096 in
        (try while true do Buffer.add_channel xml_str oc 4096 done with End_of_file -> ());
        let status = Unix.close_process_full (ic, oc, ec) in
        match status with
        | Unix.WEXITED 0 ->
            let xml = parse_xml (Buffer.contents xml_str) in
            let items = List.filter (fun c -> List.mem c.tag ["function"; "import"; "type"]) xml.children in
            Ok { mod_lang = Gleam; mod_path = path; mod_items = List.map item_of_xml items; parse_errors = [] }
        | _ ->
            Error (make_error ~file:path ~message:"tree-sitter parse failed")
      with e ->
        Error (make_error ~file:path ~message:(Printexc.to_string e)))'''

content = content.replace(old_code, new_code)

with open('lib/catseye_ast/gleam_mapper.ml', 'w') as f:
    f.write(content)

print("Done")