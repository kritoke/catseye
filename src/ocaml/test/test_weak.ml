let () =
  match Catseye_rules.Loader.load_rules "rules" with
  | Ok rules ->
    List.iter (fun r ->
      Printf.printf "Rule: %s tainted_args=%b check=%d\n"
        r.Catseye_rules.Types.id
        r.Catseye_rules.Types.conditions.requires_tainted_args
        (List.length r.Catseye_rules.Types.conditions.check_args_contain)
    ) rules
  | Error (`Msg m) -> Printf.printf "Error: %s\n" m
