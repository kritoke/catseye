(* lib/catseye_ast/plugins/crystal_plugin.ml
   Crystal language plugin descriptor.
*)

let plugin ~(extractor_registry : Catseye_engine.Extractor_registry.t) : Language_plugin.t = {
  name = "crystal";
  extensions = [".cr"];

  parse_file = (fun ~path ->
    let hier_cmd = Catseye_engine.Extractor_registry.hier_cmd extractor_registry in
    let flat_cmd = Catseye_engine.Extractor_registry.flat_cmd extractor_registry in
    (* Try hierarchical first, fall back to flat on failure *)
    match Crystal_hierarchical_mapper.parse_file ~extractor_cmd:hier_cmd ~path with
    | Ok _ as result -> result
    | Error _ -> Crystal_mapper.parse_file ~extractor_cmd:flat_cmd ~path
  );

  extract_file = Some (fun path ->
    let cmd = Catseye_engine.Extractor_registry.flat_cmd extractor_registry in
    let full_cmd = Printf.sprintf "%s '%s' 2>/dev/null" (Filename.quote cmd) (Filename.quote path) in
    try
      let (stdout_ch, stdin_ch, stderr_ch) = Unix.open_process_full full_cmd (Unix.environment ()) in
      let output = Buffer.create 4096 in
      (try while true do Buffer.add_channel output stdout_ch 4096 done
       with End_of_file -> ());
      let _ = Unix.close_process_full (stdout_ch, stdin_ch, stderr_ch) in
      let json_str = Buffer.contents output in
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
