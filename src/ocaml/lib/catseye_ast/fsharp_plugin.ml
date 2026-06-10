(* lib/catseye_ast/fsharp_plugin.ml
   F# language plugin descriptor.

   Uses F# Compiler Service (FCS) via an external extractor binary
   to produce a typed AST. The extractor is a .NET console app at
   src/extractor/fsharp/ that emits XML wire format version 1.

   See src/extractor/fsharp/README.md for the wire format spec.
   See fsharp_mapper.ml for the XML → CatseyeAST.t bridge.
*)


let plugin : Language_plugin.t = {
  name = "fsharp";
  extensions = [".fs"; ".fsx"; ".fsi"];

  parse_file = Fsharp_mapper.parse_file;

  extract_file = None;  (* Uses FCS → AST → Security_node bridge *)

  taint_sources = [
    "Console.ReadLine";
    "Console.In.ReadLine";
    "Console.ReadKey";
    "Environment.GetCommandLineArgs";
    "Environment.GetEnvironmentVariable";
    "Console.In";
    "HttpClient.GetStringAsync";
    "WebClient.DownloadString";
  ];

  taint_sinks = [
    "Console.Write";
    "Console.WriteLine";
    "printf";
    "printfn";
    "eprintf";
    "eprintfn";
    "fprintf";
    "fprintfn";
    "File.WriteAllText";
    "File.AppendAllText";
    "File.WriteAllLines";
    "File.AppendAllLines";
    "File.WriteAllBytes";
    "Process.Start";
    "HttpClient.PostAsync";
    "HttpClient.PutAsync";
    "HttpClient.SendAsync";
    "WebClient.DownloadFile";
    "SqlCommand";
  ];

  skip_calls = [
    "ignore";
    "id";
    "failwith";
    "failwithf";
    "invalidArg";
    "raise";
  ];

  manifest_files = ["fsproj"; "paket.dependencies"];
  skip_lib_dir = false;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}
