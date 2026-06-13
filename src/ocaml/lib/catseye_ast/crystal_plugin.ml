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
    match Crystal_parse_utils.run_extractor ~timeout_sec:15.0 ~extractor_cmd:extractor_cmds.flat ~path with
    | Error _ -> None
    | Ok output ->
      if output <> "" then
        try Some (Catseye_types.Security_node.decode_many (Yojson.Safe.from_string output))
        with _ -> None
      else None
  );

  taint_sources = ["params"; "request"; "env"; "ARGV"];
  taint_sinks = ["system"; "exec"; "fetch"; "File.read"; "File.write"; "HTTP::Client"];
  skip_calls = [];
  manifest_files = ["shard.yml"];
  skip_lib_dir = true;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}