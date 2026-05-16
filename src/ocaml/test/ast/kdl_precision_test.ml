(* Test: KDL precision upgrades — arg_pos and $var metavariable matching *)

open Catseye_rules.Types
open Catseye_rules.Interpreter
open Catseye_types

(* ── Helpers ────────────────────────────────────────────────────────── *)

let make_node ~name ~args ~file ~line ~taint =
  { Security_node.node_type = Security_node.Call
  ; Security_node.name = name
  ; Security_node.args = args
  ; Security_node.line = line
  ; Security_node.file = file
  ; Security_node.language = "crystal"
  ; Security_node.taint = taint
  ; Security_node.metadata = []
  }

let arg_var v = { Security_node.arg_type = Security_node.ArgVar; Security_node.value = v; Security_node.field = "" }
let arg_lit v = { Security_node.arg_type = Security_node.ArgLiteral; Security_node.value = v; Security_node.field = "" }
let _arg_call v = { Security_node.arg_type = Security_node.ArgCall; Security_node.value = v; Security_node.field = "" }

let sink ?arg_pos pattern =
  { pattern; sanitizers = []; requires_field = None; arg_pos; fix_template = None }

let check label condition =
  if condition then Printf.printf "  ✓ %s\n" label
  else Printf.printf "  ✗ FAIL: %s\n" label

(* ── Test 1: Metavariable matching ($var) ───────────────────────────── *)

let test_metavar_matching () =
  Printf.printf "\n=== Test 1: Metavariable matching ($var) ===\n\n";

  (* $client.get should match various receivers *)
  check "$client.get matches http.get"
    (matches_sink ~pattern:"$client.get" ~name:"http.get");

  check "$client.get matches client.get"
    (matches_sink ~pattern:"$client.get" ~name:"client.get");

  check "$client.get matches my_client.get"
    (matches_sink ~pattern:"$client.get" ~name:"my_client.get");

  check "$client.get matches conn.get"
    (matches_sink ~pattern:"$client.get" ~name:"conn.get");

  check "$client.get matches connection.get"
    (matches_sink ~pattern:"$client.get" ~name:"connection.get");

  (* Should NOT match different method *)
  check "$client.get does NOT match http.post"
    (not (matches_sink ~pattern:"$client.get" ~name:"http.post"));

  (* Should NOT match nested method that doesn't end in .get *)
  check "$client.get does NOT match http.get_body"
    (not (matches_sink ~pattern:"$client.get" ~name:"http.get_body"));

  (* Plain pattern without $ still works (backward compat) *)
  check "HTTP::Client.get matches via substring"
    (matches_sink ~pattern:"HTTP::Client.get" ~name:"HTTP::Client.get");

  check "HTTP::Client.get substring matches longer name"
    (matches_sink ~pattern:"HTTP::Client.get" ~name:"prefix.HTTP::Client.get.suffix");

  (* Edge: bare $fn matches anything *)
  check "$fn matches any name"
    (matches_sink ~pattern:"$fn" ~name:"anything.at.all");

  (* Edge: empty pattern *)
  check "empty pattern does not match"
    (not (matches_sink ~pattern:"" ~name:"anything"))

(* ── Test 2: Arg position matching ──────────────────────────────────── *)

let test_arg_pos () =
  Printf.printf "\n=== Test 2: Arg position matching (arg=N) ===\n\n";

  let ctx = make_taint_context
    ~global:["url"; "target"]
    ~by_file:[("test.cr", ["url"; "target"])]
    () in

  (* Node: HTTP::Client.get(url, headers)
     arg 0 = url (tainted), arg 1 = "Accept: text/html" (literal) *)
  let node_tainted_first = make_node
    ~name:"HTTP::Client.get"
    ~args:[arg_var "url"; arg_lit "Accept: text/html"]
    ~file:"test.cr" ~line:10 ~taint:false in

  (* Node: HTTP::Client.get("https://safe.com", url)
     arg 0 = literal (safe), arg 1 = url (tainted) *)
  let node_tainted_second = make_node
    ~name:"HTTP::Client.get"
    ~args:[arg_lit "https://safe.com"; arg_var "url"]
    ~file:"test.cr" ~line:20 ~taint:false in

  (* Node: HTTP::Client.get("https://safe.com", "Accept: text/html")
     No tainted args *)
  let node_no_taint = make_node
    ~name:"HTTP::Client.get"
    ~args:[arg_lit "https://safe.com"; arg_lit "Accept: text/html"]
    ~file:"test.cr" ~line:30 ~taint:false in

  (* Rule with arg=0: only first arg position matters *)
  let sink_arg0 = sink ~arg_pos:0 "HTTP::Client.get" in
  let rule_arg0 = { id = "SSRF"; severity = "High"; sinks = [sink_arg0];
                    sources = [{ name = "url"; field = None }];
                    conditions = { (default_conditions ()) with requires_tainted_args = true };
                    message_template = "SSRF via {sink}" } in

  check "arg=0: flags when tainted data is first arg"
    (let findings = check_rule rule_arg0 [node_tainted_first] ctx in
     List.length findings = 1);

  check "arg=0: does NOT flag when tainted data is second arg"
    (let findings = check_rule rule_arg0 [node_tainted_second] ctx in
     List.length findings = 0);

  check "arg=0: does NOT flag when no tainted args"
    (let findings = check_rule rule_arg0 [node_no_taint] ctx in
     List.length findings = 0);

  (* Rule without arg: any tainted arg triggers (backward compat) *)
  let sink_no_arg = sink "HTTP::Client.get" in
  let rule_no_arg = { rule_arg0 with sinks = [sink_no_arg] } in

  check "no arg: flags when tainted data is first arg"
    (let findings = check_rule rule_no_arg [node_tainted_first] ctx in
     List.length findings = 1);

  check "no arg: flags when tainted data is second arg"
    (let findings = check_rule rule_no_arg [node_tainted_second] ctx in
     List.length findings = 1);

  check "no arg: does NOT flag when no tainted args"
    (let findings = check_rule rule_no_arg [node_no_taint] ctx in
     List.length findings = 0);

  (* Rule with arg=1: only second arg position matters *)
  let sink_arg1 = sink ~arg_pos:1 "HTTP::Client.get" in
  let rule_arg1 = { rule_arg0 with sinks = [sink_arg1] } in

  check "arg=1: does NOT flag when tainted data is first arg"
    (let findings = check_rule rule_arg1 [node_tainted_first] ctx in
     List.length findings = 0);

  check "arg=1: flags when tainted data is second arg"
    (let findings = check_rule rule_arg1 [node_tainted_second] ctx in
     List.length findings = 1)

(* ── Test 3: KDL parsing of arg property ────────────────────────────── *)

let test_kdl_parsing () =
  Printf.printf "\n=== Test 3: KDL parsing of arg property ===\n\n";

  let kdl_with_arg = {|
rule "TestRule" severity="High" {
    sinks {
        sink "HTTP::Client.get" arg=0 {
            sanitizer "URI.parse"
        }
        sink "File.read" arg=1
    }
    sources {
        source "url"
    }
    message "Test finding via {sink}"
}
|} in

  match Catseye_rules.Loader.parse_string kdl_with_arg with
  | Error (`Msg msg) ->
    Printf.printf "  ✗ FAIL: KDL parse error: %s\n" msg
  | Ok rules ->
    let rule = List.hd rules in
    check "parsed rule id" (rule.id = "TestRule");

    let sinks = rule.sinks in
    check "parsed 2 sinks" (List.length sinks = 2);

    (match sinks with
     | [s1; s2] ->
       check "first sink has arg_pos=0" (s1.arg_pos = Some 0);
       check "first sink has sanitizer" (s1.sanitizers = ["URI.parse"]);
       check "second sink has arg_pos=1" (s2.arg_pos = Some 1);
       check "second sink has no sanitizers" (s2.sanitizers = [])
     | _ -> Printf.printf "  ✗ FAIL: unexpected sink count\n");

    (* KDL without arg property *)
    let kdl_no_arg = {|
rule "NoArg" severity="Medium" {
    sinks {
        sink "File.read"
    }
    sources {
        source "path"
    }
    message "Path traversal via {sink}"
}
|} in
    (match Catseye_rules.Loader.parse_string kdl_no_arg with
     | Ok rules ->
       let sink = List.hd (List.hd rules).sinks in
       check "sink without arg has arg_pos=None" (sink.arg_pos = None)
     | Error _ -> Printf.printf "  ✗ FAIL: KDL parse error for no-arg rule\n")

(* ── Test 3b: KDL parsing of fix property ──────────────────────────── *)

let () =
  Printf.printf "\n=== Test 3b: KDL parsing of fix property ===\n\n";
  let kdl_with_fix = {|
rule "TestFix" severity="High" {
    sinks {
        sink "HTTP::Client.get" arg=0 fix="HTTP::Client.get(URI.parse({arg0}))"
    }
    sources {
        source "url"
    }
    message "SSRF via {sink}"
}
|} in
  (match Catseye_rules.Loader.parse_string kdl_with_fix with
   | Ok rules ->
     let rule = List.hd rules in
     let sink = List.hd rule.sinks in
     check "sink has fix_template" (sink.fix_template = Some "HTTP::Client.get(URI.parse({arg0}))");
     let instantiated = Catseye_rules.Interpreter.instantiate_fix
       (Option.get sink.fix_template) ~sink_name:"HTTP::Client.get"
       [Catseye_types.Security_node.{ arg_type = ArgVar; value = "url"; field = "" }] in
     check "instantiate_fix replaces {arg0}" (instantiated = "HTTP::Client.get(URI.parse(url))")
   | Error (`Msg msg) ->
     Printf.printf "  ✗ FAIL: KDL parse error: %s\n" msg)

(* ── Test 4: Combined $var + arg_pos ────────────────────────────────── *)

let test_combined () =
  Printf.printf "\n=== Test 4: Combined $var metavariable + arg_pos ===\n\n";

  let ctx = make_taint_context
    ~global:["url"]
    ~by_file:[("test.cr", ["url"])]
    () in

  (* Rule: sink "$client.get" arg=0 *)
  let rule = { id = "SSRF"; severity = "High";
               sinks = [sink ~arg_pos:0 "$client.get"];
               sources = [{ name = "url"; field = None }];
               conditions = { (default_conditions ()) with requires_tainted_args = true };
               message_template = "SSRF via {sink}" } in

  (* conn.get(url, headers) — matches $client.get, url in arg 0 *)
  let node_hit = make_node
    ~name:"conn.get"
    ~args:[arg_var "url"; arg_lit "headers"]
    ~file:"test.cr" ~line:5 ~taint:false in

  (* conn.get("safe", url) — matches $client.get, url in arg 1 (wrong position) *)
  let node_miss_pos = make_node
    ~name:"conn.get"
    ~args:[arg_lit "safe"; arg_var "url"]
    ~file:"test.cr" ~line:10 ~taint:false in

  (* http.post(url) — does NOT match $client.get (different method) *)
  let node_wrong_method = make_node
    ~name:"http.post"
    ~args:[arg_var "url"]
    ~file:"test.cr" ~line:15 ~taint:false in

  check "$client.get + arg=0: hits conn.get(url, ...)"
    (let findings = check_rule rule [node_hit] ctx in List.length findings = 1);

  check "$client.get + arg=0: misses conn.get(..., url)"
    (let findings = check_rule rule [node_miss_pos] ctx in List.length findings = 0);

  check "$client.get + arg=0: misses http.post(url)"
    (let findings = check_rule rule [node_wrong_method] ctx in List.length findings = 0)

(* ── Run all tests ──────────────────────────────────────────────────── *)

let () =
  Printf.printf "=== KDL Precision Tests ===\n";
  test_metavar_matching ();
  test_arg_pos ();
  test_kdl_parsing ();
  test_combined ();
  Printf.printf "\n=== Done ===\n"
