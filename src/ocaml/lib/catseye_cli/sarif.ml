(* lib/catseye_cli/sarif.ml
   SARIF (Static Analysis Results Interchange Format) output.
   Produces SARIF 2.1.0 compatible JSON from findings and DAGs. *)

open Catseye_types

let severity_to_sarif = function
  | "Critical" | "critical" -> "error"
  | "High" | "high" -> "error"
  | "Medium" | "medium" -> "warning"
  | "Low" | "low" -> "note"
  | _ -> "warning"

let finding_to_result f =
  let location =
    `Assoc [
      ("physicalLocation", `Assoc [
        ("artifactLocation", `Assoc [
          ("uri", `String f.Finding.file);
        ]);
        ("region", `Assoc [
          ("startLine", `Int f.Finding.line);
        ]);
      ]);
    ] in
  let flow_steps = List.mapi (fun i (step : Finding.flow_step) ->
    `Assoc [
      ("location", `Assoc [
        ("physicalLocation", `Assoc [
          ("artifactLocation", `Assoc [("uri", `String step.Finding.file)]);
          ("region", `Assoc [("startLine", `Int step.Finding.line)]);
        ]);
      ]);
      ("message", `Assoc [("text", `String step.Finding.message)]);
    ]
  ) f.Finding.flow in
  `Assoc [
    ("ruleId", `String f.Finding.rule);
    ("level", `String (severity_to_sarif f.Finding.severity));
    ("message", `Assoc [("text", `String f.Finding.message)]);
    ("locations", `List [location]);
    (if flow_steps <> [] then
      ("codeFlows", `List [
        `Assoc [
          ("threadFlows", `List [
            `Assoc [
              ("locations", `List flow_steps);
            ]
          ]);
        ]
      ])
    else
      ("codeFlows", `List []));
  ]

let to_sarif (findings : Finding.t list) : string =
  let rules = List.map (fun f ->
    `Assoc [
      ("id", `String f.Finding.rule);
      ("shortDescription", `Assoc [("text", `String f.Finding.message)]);
    ]
  ) findings in
  let unique_rules =
    List.sort_uniq (fun a b ->
      let get_id = function `Assoc l -> (match List.assoc_opt "id" l with Some (`String s) -> s | _ -> "") | _ -> "" in
      String.compare (get_id a) (get_id b)
    ) rules in
  let sarif = `Assoc [
    ("$schema", `String "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json");
    ("version", `String "2.1.0");
    ("runs", `List [
      `Assoc [
        ("tool", `Assoc [
          ("driver", `Assoc [
            ("name", `String "catseye");
            ("version", `String Catseye_engine.Engine.version);
            ("rules", `List unique_rules);
          ]);
        ]);
        ("results", `List (List.map finding_to_result findings));
      ]
    ])
  ] in
  Yojson.Safe.pretty_to_string sarif
