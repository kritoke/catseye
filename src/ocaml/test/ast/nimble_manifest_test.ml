(* test/nimble_manifest_test.ml
   Golden test for Crow's Nest Nimble manifest parsing.

   Covers the three `requires` forms (bare name, version range, GitHub URL),
   nimble.lock JSON extraction, and the locked-wins discovery rule.
   Pure parsing — no network. *)

let show_dep (d : Catseye_crowsnest.Manifest.shard_dep) =
  Printf.sprintf "{name=%s; version=%s; github=%s}"
    d.Catseye_crowsnest.Manifest.name
    (match d.Catseye_crowsnest.Manifest.version with
     | Some v -> v | None -> "-")
    (match d.Catseye_crowsnest.Manifest.github with
     | Some g -> g | None -> "-")

let () =
  Printf.printf "=== Nimble manifest parsing test ===\n";

  let candidates dir = [
    Filename.concat dir "tests/fixtures/nimble";      (* cwd = repo root *)
    Filename.concat dir "../../tests/fixtures/nimble"; (* cwd = src/ocaml *)
    Filename.concat dir "../../../tests/fixtures/nimble"; (* cwd = src/ocaml/test *)
    Filename.concat dir "../../../../tests/fixtures/nimble"; (* cwd = src/ocaml/test/ast *)
  ] in
  let base_dir =
    Stdlib.List.find_opt (fun d ->
      Sys.file_exists (Filename.concat d "sample.nimble")) (candidates ".")
  in
  (match base_dir with
   | None ->
     Printf.printf "SKIP: fixtures not found (probed repo-relative paths)\n";
     exit 0
   | Some dir ->

  (* 1. .nimble parsing: three requires forms *)
  (match Catseye_crowsnest.Manifest.parse_nimble (Filename.concat dir "sample.nimble") with
   | Error (`Msg m) -> Printf.printf "FAIL: .nimble parse: %s\n" m; exit 1
   | Ok deps ->
     Printf.printf ".nimble deps (%d):\n" (Stdlib.List.length deps);
     Stdlib.List.iter (fun d -> Printf.printf "  %s\n" (show_dep d)) deps;
     let names = Stdlib.List.map (fun (d : Catseye_crowsnest.Manifest.shard_dep) ->
       d.Catseye_crowsnest.Manifest.name) deps in
     (* bare name *)
     if not (Stdlib.List.mem "httpbeast" names) then begin
       Printf.printf "FAIL: bare-name form not parsed\n"; exit 1
     end;
     (* version range *)
     let jester = Stdlib.List.find (fun (d : Catseye_crowsnest.Manifest.shard_dep) ->
       d.Catseye_crowsnest.Manifest.name = "jester") deps in
     (match jester.Catseye_crowsnest.Manifest.version with
      | Some v when v = ">= 0.5.0" -> ()
      | v -> Printf.printf "FAIL: jester version wrong: %s\n"
               (match v with Some s -> s | None -> "none"); exit 1);
     (* GitHub URL: dep name = repo, github = owner/repo *)
     let chronos = Stdlib.List.find (fun (d : Catseye_crowsnest.Manifest.shard_dep) ->
       d.Catseye_crowsnest.Manifest.name = "chronos") deps in
     (match chronos.Catseye_crowsnest.Manifest.github with
      | Some g when g = "dom96/chronos" -> ()
      | g -> Printf.printf "FAIL: chronos github wrong: %s\n"
               (match g with Some s -> s | None -> "none"); exit 1);
     Printf.printf ".nimble three-form assertions: OK\n");

  (* 2. nimble.lock parsing: exact versions *)
  (match Catseye_crowsnest.Manifest.parse_nimble_lock (Filename.concat dir "nimble.lock") with
   | Error (`Msg m) -> Printf.printf "FAIL: nimble.lock parse: %s\n" m; exit 1
   | Ok deps ->
     Printf.printf "nimble.lock deps (%d):\n" (Stdlib.List.length deps);
     Stdlib.List.iter (fun d -> Printf.printf "  %s\n" (show_dep d)) deps;
     let hb = Stdlib.List.find (fun (d : Catseye_crowsnest.Manifest.shard_dep) ->
       d.Catseye_crowsnest.Manifest.name = "httpbeast") deps in
     (match hb.Catseye_crowsnest.Manifest.version with
      | Some v when v = "0.4.4" -> Printf.printf "nimble.lock exact-version assertion: OK\n"
      | v -> Printf.printf "FAIL: httpbeast locked version: %s\n"
               (match v with Some s -> s | None -> "none"); exit 1));

  (* 3. Locked-wins discovery: dir has BOTH nimble.lock and sample.nimble →
     only Nimble_lock must be discovered *)
  let found = Catseye_crowsnest.Manifest.find_manifests dir in
  let has_lock = Stdlib.List.exists (fun m ->
    match m with Catseye_crowsnest.Manifest.Nimble_lock _ -> true | _ -> false) found in
  let has_plain = Stdlib.List.exists (fun m ->
    match m with Catseye_crowsnest.Manifest.Nimble _ -> true | _ -> false) found in
  Printf.printf "discovery: lock=%b plain=%b\n" has_lock has_plain;
  if has_plain && has_lock then begin
    Printf.printf "FAIL: both lock and plain .nimble discovered (lock must win)\n"; exit 1
  end;
  if not has_lock then begin
    Printf.printf "FAIL: nimble.lock not discovered\n"; exit 1
  end;
  Printf.printf "locked-wins assertion: OK\n";

  Printf.printf "=== All nimble manifest tests passed ===\n")
