let () =
  let kdl_str = {kdl|
rule "TestFix" severity="High" {
    sinks {
        sink "HTTP::Client.get" arg=0 fix="wrap({arg0})"
    }
    sources {
        source "url"
    }
    message "Test: {sink}"
}
|kdl} in
  match Kdl.of_string kdl_str with
  | Ok doc ->
    List.iter (fun (node : Kdl.node) ->
      List.iter (fun (child : Kdl.node) ->
        if child.name = "sinks" then
          List.iter (fun (sink : Kdl.node) ->
            Printf.printf "sink: name=%s props:\n" sink.name;
            List.iter (fun (k, (_, v) : string * (string * Kdl.value)) ->
              let val_str = match v with
                | `String s -> Printf.sprintf "\"%s\"" s
                | #Kdl.Num.t as n -> Printf.sprintf "num:%s" (Kdl.Num.to_string n)
                | _ -> "other"
              in
              Printf.printf "  %s = %s\n" k val_str
            ) sink.props;
            Printf.printf "  args:\n";
            List.iter (fun (ty, v) ->
              let val_str = match v with
                | `String s -> Printf.sprintf "\"%s\"" s
                | _ -> "other"
              in
              Printf.printf "    %s\n" val_str
            ) sink.args
          ) child.children
      ) node.children
    ) doc
  | Error (msg, _) ->
    Printf.eprintf "Parse error: %s\n" msg
