(* Regression test for the .catseye.toml config loader.

   Before the fix, the three get_* helpers in config.ml caught only
   Not_found_s, but Toml.Types.Table.find (= Map.find) raises plain
   Not_found for absent keys. The escaped exception hit load_toml's
   "with _ -> cfg", silently dropping the ENTIRE config overlay on
   effectively every real config (most keys are absent in any given file).
   [claws.suppress], [ai.suppress], [taint.suppress], thresholds, and
   enable flags were all ignored.

   This test loads a config that sets only a few keys (leaving most absent)
   and asserts the present keys are applied. If the Not_found regression
   returns, load_toml drops the overlay and the assertions fail. *)

open Base

let () =
  (* A config that deliberately sets only a FEW keys, leaving most absent.
     Before the fix, the absent keys (languages.enabled, scan.exclude, etc.)
     aborted the whole overlay. *)
  let toml = {|
[taint.suppress]
SSRF = ["**/remote_theme.cr"]

[claws.suppress]
RefusedParentBequest = ["**/plugins/**/*.cr"]

[claws]
max_params = 7
|} in
  let path = "/tmp/catseye_config_test.toml" in
  let oc = Stdlib.open_out path in
  Stdlib.output_string oc toml;
  Stdlib.close_out oc;

  let cfg = Catseye_cli.Config.default in
  let cfg' = Catseye_cli.Config.load_toml path cfg in
  Stdlib.Sys.remove path;

  (* 1. [taint.suppress] must be applied *)
  let taint_n =
    Map.length (cfg'.Catseye_cli.Config.taint_suppress : string list Map.M(String).t)
  in
  Stdlib.Printf.printf "taint_suppress entries: %d\n" taint_n;
  assert (taint_n = 1);

  (* 2. [claws.suppress] must be applied (the headline bug) *)
  let claws_n = Map.length cfg'.claws_config.suppress in
  Stdlib.Printf.printf "claws_config.suppress entries: %d\n" claws_n;
  assert (claws_n = 1);

  (* 3. A present [claws] key (max_params) must be applied *)
  Stdlib.Printf.printf "max_params: %d\n" cfg'.claws_config.max_params;
  assert (cfg'.claws_config.max_params = 7);

  (* 4. An absent key must keep its default (not abort the overlay).
     claws.complexity_warning is unset above, so it should be the default 10. *)
  Stdlib.Printf.printf "complexity_warning (absent -> default): %d\n"
    cfg'.claws_config.complexity_warning;
  assert (cfg'.claws_config.complexity_warning = 10);

  Stdlib.Printf.printf "OK: .catseye.toml overlay applied with absent keys using defaults\n"
