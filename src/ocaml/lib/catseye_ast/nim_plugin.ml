(* lib/catseye_ast/nim_plugin.ml
   Nim language plugin descriptor.

   Nim uses tree-sitter exclusively via Nim_mapper.
   No extractor registry needed for this language.
*)

let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )

let plugin : Language_plugin.t = {
  name = "nim";
  extensions = [".nim"; ".nims"];

  parse_file = Nim_mapper.parse_file;

  extract_file = None;  (* Uses tree-sitter via parse_file *)

  (* Taint sources: user-controlled input functions from Nim stdlib *)
  taint_sources = [
    (* os module *)
    "os.getEnv"; "os.getEnvOrDefault"; "os.commandLineParams"; "os.paramStr"; "os.paramCount";
    (* std/streams *)
    "streams.readLine"; "streams.readAll"; "streams.readStr";
    (* std/httpclient *)
    "httpclient.getContent"; "httpclient.postContent"; "httpclient.get"; "httpclient.post";
    (* std/net *)
    "net.recv"; "net.recvFrom"; "net.recvLine";
    (* std/asyncnet *)
    "asyncnet.recv"; "asyncnet.recvLine";
    (* system / io *)
    "stdin.readLine"; "readLine"; "readAll"; "readFile";
    (* std/uri *)
    "uri.parseUri";
    (* std/json *)
    "json.parseJson";
    (* std/strutils *)
    "strutils.split"; "strutils.strip";
  ];

  (* Taint sinks: functions that can cause security issues if given user input *)
  taint_sinks = [
    (* Command injection *)
    "os.execCmd"; "os.execShellCmd"; "osproc.startProcess"; "osproc.execProcess";
    "osproc.createProcess"; "os.shell";
    (* File system *)
    "system.writeFile"; "system.open"; "system.write";
    "streams.write"; "streams.writeLine";
    "os.removeDir"; "os.createDir"; "os.copyFile"; "os.moveFile"; "os.removeFile";
    "os.rename"; "os.symlink";
    (* Network *)
    "net.send"; "net.sendTo";
    "httpclient.getContent"; "httpclient.postContent"; "httpclient.get"; "httpclient.post";
    "asyncnet.send";
    (* Deserialization *)
    "marshal.load"; "marshal.store";
    "json.to"; "json.fromJson";
    (* Logging with user data *)
    "system.echo";
    (* SQL *)
    "db_sqlite.getValue"; "db_sqlite.getRow"; "db_sqlite.getAllRows";
    "db_sqlite.exec"; "db_sqlite.tryExec";
    "db_postgres.getValue"; "db_postgres.getRow"; "db_postgres.getAllRows";
    "db_mysql.getValue"; "db_mysql.getRow"; "db_mysql.getAllRows";
  ];

  (* Skip calls: functions that don't propagate taint *)
  skip_calls = [
    (* String inspection (not sinks) *)
    "strutils.contains"; "strutils.startsWith"; "strutils.endsWith";
    "strutils.len"; "strutils.count"; "strutils.find";
    "strutils.parseInt"; "strutils.parseFloat";
    (* Type conversions *)
    "system.`$`"; "system.int"; "system.float"; "system.bool"; "system.char";
    "system.ord"; "system.chr"; "system.high"; "system.low"; "system.succ"; "system.pred";
    (* Math *)
    "math.abs"; "math.min"; "math.max"; "math.sqrt"; "math.ln"; "math.log";
    "math.sin"; "math.cos"; "math.tan"; "math.floor"; "math.ceil"; "math.round";
    (* System info *)
    "system.getCurrentException"; "system.getStackTrace";
    (* Debugging *)
    "system.repr"; "system.`typeof`";
  ];

  manifest_files = ["*.nimble"; "nimble.lock"; "nim.cfg"; "config.nims"];
  skip_lib_dir = false;

  supports_ast_bridge = true;
  supports_il_cfg = true;
}
