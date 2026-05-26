(* lib/catseye_cli/sarif.ml
   SARIF (Static Analysis Results Interchange Format) output.
   Produces SARIF 2.1.0 compatible JSON from findings and DAGs. *)

open Base
let ( = ) = Stdlib.( = )
let ( <> ) = Stdlib.( <> )
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
  let flow_steps = List.map ~f:(fun (step : Finding.flow_step) ->
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
  (* Build codeFlows: taint flow + optional reachability path *)
  let taint_flow =
    if flow_steps <> [] then [
      `Assoc [
        ("threadFlows", `List [
          `Assoc [
            ("locations", `List flow_steps);
          ]
        ]);
      ]
    ] else []
  in
  let reach_flow = match f.Finding.reachability with
    | Some r when r.path <> [] ->
      let entry_step = match r.entry_point with
        | Some ep ->
          let (ep_file, ep_line) = match r.path with
            | (pf, pl) :: _ -> (pf, pl)
            | [] -> ("", 0)
          in
          [`Assoc [
            ("location", `Assoc [
              ("physicalLocation", `Assoc [
                ("artifactLocation", `Assoc [("uri", `String ep_file)]);
                ("region", `Assoc [("startLine", `Int ep_line)]);
              ]);
            ]);
            ("message", `Assoc [("text", `String (Stdlib.Printf.sprintf "Entry point: %s" ep))]);
          ]]
        | None -> []
      in
      let path_steps = List.map ~f:(fun (pf, pl) ->
        `Assoc [
          ("location", `Assoc [
            ("physicalLocation", `Assoc [
              ("artifactLocation", `Assoc [("uri", `String pf)]);
              ("region", `Assoc [("startLine", `Int pl)]);
            ]);
          ]);
          ("message", `Assoc [("text",
            `String (Stdlib.Printf.sprintf "Reachable from entry point (%s)"
              (match r.entry_function with Some fn -> fn | None -> "unknown")))]);
        ]
      ) r.path in
      let all_locations = entry_step @ path_steps in
      [`Assoc [
        ("threadFlows", `List [
          `Assoc [
            ("locations", `List all_locations);
          ]
        ]);
      ]]
    | _ -> []
  in
  let base_result = [
    ("ruleId", `String f.Finding.rule);
    ("level", `String (severity_to_sarif f.Finding.severity));
    ("message", `Assoc [("text", `String f.Finding.message)]);
    ("locations", `List [location]);
  ] in
  let with_code_flows =
    let all_flows = taint_flow @ reach_flow in
    if all_flows <> [] then
      ("codeFlows", `List all_flows) :: base_result
    else
      ("codeFlows", `List []) :: base_result
  in
  let with_reachability = match f.Finding.reachability with
    | Some r ->
      let reach_props = [
        ("status", `String (match r.status with
          | Finding.Live -> "live"
          | Finding.Dormant -> "dormant"
          | Finding.Safe -> "safe"));
        ("pathLength", `Int r.path_length);
      ] in
      let reach_props' = match r.entry_function with
        | Some fn -> ("entryFunction", `String fn) :: reach_props
        | None -> reach_props
      in
      ("properties", `Assoc [
        ("reachability", `Assoc reach_props');
      ]) :: with_code_flows
    | None -> with_code_flows
  in
  let with_suggestion = match f.Finding.suggestion with
    | Some s ->
      (match List.Assoc.find ~equal:String.equal with_reachability "properties" with
       | Some (`Assoc props) ->
         ("properties", `Assoc (("suggestion", `String s) :: props)) ::
         (List.filter ~f:(fun (k, _) -> k <> "properties") with_reachability)
       | _ ->
         ("properties", `Assoc [("suggestion", `String s)]) :: with_reachability)
    | None -> with_reachability
  in
  `Assoc with_suggestion

(** Build a supply chain SCA result for a dependency vulnerability. *)
let sca_result (name : string) (version : string option) (ecosystem : string)
    (cve_id : string) (summary : string) (severity : string option)
    (patched : string list) : Yojson.Safe.t =
  let level = match severity with
    | Some s when String.contains s 'C' || String.contains s 'H' -> "error"
    | Some _ -> "warning"
    | None -> "warning"
  in
  `Assoc [
    ("ruleId", `String ("SCA/" ^ cve_id));
    ("level", `String level);
    ("message", `Assoc [("text", `String summary)]);
    ("locations", `List [
      `Assoc [
        ("physicalLocation", `Assoc [
          ("artifactLocation", `Assoc [
            ("uri", `String (Stdlib.Printf.sprintf "%s/%s" ecosystem name));
          ]);
        ]);
      ]
    ]);
    ("properties", `Assoc [
      ("supplyChain", `Assoc [
        ("dependency", `String name);
        ("version", match version with Some v -> `String v | None -> `Null);
        ("ecosystem", `String ecosystem);
        ("vulnerabilityId", `String cve_id);
        ("patchedVersions", `List (List.map ~f:(fun pv -> `String pv) patched));
      ]);
    ]);
  ]

(** Build supply chain results from Crow's Nest data. *)
let crows_nest_results (supply_chain : Yojson.Safe.t) : Yojson.Safe.t list =
  let open Yojson.Safe.Util in
  let deps = match member "dependencies" supply_chain with
    | `List l -> l
    | _ -> []
  in
  List.filter_map ~f:(fun dep ->
    let name = to_string (member "name" dep) in
    let version = match member "version" dep with `String s -> Some s | _ -> None in
    let ecosystem = to_string (member "ecosystem" dep) in
    let osv = member "osv" dep in
    match member "status" osv with
    | `String "vulnerable" ->
      (match member "vulnerabilities" osv with
       | `List vulns ->
         (* Return first vulnerability as SARIF result *)
         (match vulns with
          | v :: _ ->
            let cve_id = to_string (member "id" v) in
            let summary = to_string (member "summary" v) in
            let severity = match member "severity" v with `String s -> Some s | _ -> None in
            let patched = match member "patched_versions" v with
              | `List l -> List.filter_map ~f:(function `String s -> Some s | _ -> None) l
              | _ -> []
            in
            Some (sca_result name version ecosystem cve_id summary severity patched)
          | [] -> None)
       | _ -> None)
    | _ -> None
  ) deps

let to_sarif (findings : Finding.t list)
    ?(supply_chain : Yojson.Safe.t option) () : string =
  let rules = List.map ~f:(fun f ->
    `Assoc [
      ("id", `String f.Finding.rule);
      ("shortDescription", `Assoc [("text", `String f.Finding.message)]);
    ]
  ) findings in
  let sca_rules = match supply_chain with
    | Some sc ->
      let deps = match Yojson.Safe.Util.member "dependencies" sc with
        | `List l -> l
        | _ -> []
      in
      List.filter_map ~f:(fun dep ->
        let osv = Yojson.Safe.Util.member "osv" dep in
        match Yojson.Safe.Util.member "status" osv with
        | `String "vulnerable" ->
          (match Yojson.Safe.Util.member "vulnerabilities" osv with
           | `List (v :: _) ->
             Some (`Assoc [
               ("id", `String ("SCA/" ^ Yojson.Safe.Util.to_string (Yojson.Safe.Util.member "id" v)));
               ("shortDescription", `Assoc [("text", `String (Yojson.Safe.Util.to_string (Yojson.Safe.Util.member "summary" v)))]);
             ])
           | _ -> None)
        | _ -> None
      ) deps
    | None -> []
  in
  let unique_rules =
    Stdlib.List.sort_uniq(fun a b ->
      let get_id = function `Assoc l -> (match List.Assoc.find ~equal:String.equal l "id" with Some (`String s) -> s | _ -> "") | _ -> "" in
      String.compare (get_id a) (get_id b)
    ) (rules @ sca_rules)
  in
  let sca_res = match supply_chain with
    | Some sc -> crows_nest_results sc
    | None -> []
  in
  let all_results = List.map ~f:finding_to_result findings @ sca_res in
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
        ("results", `List all_results);
      ]
    ])
  ] in
  Yojson.Safe.pretty_to_string sarif
