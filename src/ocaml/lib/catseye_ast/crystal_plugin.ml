(* lib/catseye_ast/crystal_plugin.ml
   Crystal language plugin descriptor.
   
   This plugin receives extractor commands as parameters from the engine,
   keeping catseye.ast as a pure leaf library with no engine dependency.
 *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

let plugin ~(extractor_cmds : Catseye_types.Extractor_cmds.t) : Language_plugin.t = {
  name = "crystal";
  extensions = [".cr"];

  parse_file = (fun ~path ->
    (* Try hierarchical first, fall back to flat on failure *)
    match Crystal_hierarchical_mapper.parse_file ~extractor_cmd:extractor_cmds.hier ~path with
    | Ok _ as result -> result
    | Error _ -> Crystal_mapper.parse_file ~extractor_cmd:extractor_cmds.flat ~path
  );

  extract_file = Some (fun path ->
    let full_cmd = Stdlib.Printf.sprintf "%s '%s' 2>/dev/null" 
      (Stdlib.Filename.quote extractor_cmds.flat) 
      (Stdlib.Filename.quote path) in
    try
      let (stdout_ch, stdin_ch, stderr_ch) = Unix.open_process_full full_cmd (Unix.environment ()) in
      let output = Stdlib.Buffer.create 4096 in
      (try while true do Stdlib.Buffer.add_channel output stdout_ch 4096 done
       with Stdlib.End_of_file -> ());
      let _ = Unix.close_process_full (stdout_ch, stdin_ch, stderr_ch) in
      let json_str = Stdlib.Buffer.contents output in
      if json_str <> "" then
        try Some (Catseye_types.Security_node.decode_many (Yojson.Safe.from_string json_str))
        with _ -> None
      else None
    with _ -> None
  );

  taint_sources = ["params"; "request"; "env"; "ARGV"];
  taint_sinks = ["system"; "exec"; "fetch"; "File.read"; "File.write"; "HTTP::Client"];
  skip_calls = [];
  manifest_files = ["shard.yml"];
  skip_lib_dir = true;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}