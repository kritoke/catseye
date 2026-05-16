# Autofix Spec

## Type Changes

### `types.ml` — sink_def

```ocaml
type sink_def = {
  name : string;
  sanitizers : string list;
  arg_pos : int option;     (* already exists *)
  fix_template : string option;  (* NEW *)
}
```

### `loader.ml` — parse fix from KDL

```ocaml
let parse_sink (node : Kdl.Node.t) : sink_def =
  let fix = get_prop node "fix" in  (* string option *)
  { name = node.name; sanitizers; arg_pos; fix_template = fix }
```

### `interpreter.ml` — instantiate fix template

When a sink match is found and `fix_template` is `Some template`:

```ocaml
let instantiate_fix (template : string) (tainted_vars : string list) : string =
  (* Replace {arg0} with first tainted var, {arg1} with second, etc. *)
  let args = Array.of_list tainted_vars in
  let re = Str.regexp "{arg[0-9]+}" in
  Str.global_substitute re (fun s ->
    let m = Str.matched_string s in
    let idx = int_of_string (String.sub m 5 (String.length m - 6)) in
    if idx < Array.length args then args.(idx) else m
  ) template
```

Add `suggestion` to the finding returned from `check_sinks` / `check_call_sinks`.

### `orchestrator.ml` — render in terminal

```ocaml
(* After printing each finding *)
(match finding.Finding.suggestion with
 | Some fix -> Printf.printf "  💡 Suggestion: %s\n" fix
 | None -> ())
```

### SARIF output

Map `suggestion` to SARIF `fix` object:

```json
{
  "fixes": [{
    "description": { "text": "Wrap in URI.parse" },
    "artifactChanges": [{
      "artifactLocation": { "uri": "src/foo.cr" },
      "replacements": [{
        "deletedRegion": { "startLine": 10 },
        "insertedContent": { "text": "HTTP::Client.get(URI.parse(url))" }
      }]
    }]
  }]
}
```

Note: Full SARIF fix support requires knowing the exact replacement range. For now, populate `suggestion` as a text hint. Full SARIF edits can come later.

## KDL Rule Updates

Add `fix` to primary sinks in 5 rules:

### ssrf.kdl
```kdl
sink "HTTP::Client.get" arg=0 {
    sanitizer "URI.parse"
    fix "HTTP::Client.get(URI.parse({arg0}))"
}
```

### path_traversal.kdl
```kdl
sink "File.read" arg=0 {
    sanitizer "File.expand_path"
    fix "File.read(File.expand_path({arg0}))"
}
```

### sql_injection.kdl
```kdl
sink "db.query" arg=0 {
    fix "Use parameterized queries instead of string interpolation"
}
```

### command_injection.kdl
```kdl
sink "system" arg=0 {
    sanitizer "Shell.escape"
    fix "Use Process.run([\"command\", {arg0}]) instead of shell string"
}
```

### open_redirect.kdl
```kdl
sink "redirect" arg=0 {
    fix "redirect(validate_url({arg0}))"
}
```
