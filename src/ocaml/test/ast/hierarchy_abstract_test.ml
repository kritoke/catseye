(* Regression test for abstract-class / abstract-def awareness in
   hierarchy smell detectors.

   Before the fix, catseye detected abstract classes only by a substring
   match on the class name (the literal "abstract"), and treated every
   small override as "Refused Parent Bequest". That produced a large block
   of false positives on idiomatic Crystal:

     - BaseClassShouldBeAbstract fired on abstract bases whose name did not
       contain "abstract" (e.g. `abstract class Processor`).
     - RefusedParentBequest fired on subclasses fulfilling an `abstract def`
       contract from their parent, and on `initialize` constructors.

   The Crystal extractor now emits `("abstract","true")` metadata on Class
   and Def nodes; the detectors consult that metadata. This test builds the
   node list directly (mirroring the extractor output) and asserts the
   detectors stay quiet. If either signal regresses, the assertions fail. *)

let () =
  let module S = Catseye_types.Security_node in

  (* Build a security node mirroring the flat extractor's output. *)
  let mk node_type name line metadata =
    { S.node_type; name; args = []; line; taint = false;
      file = "test.cr"; language = "crystal"; metadata }
  in

  (* abstract class Base
       abstract def render
       abstract def priority
     class A < Base ... overrides both (tiny bodies)
     class B < Base ...
     class C < Base ...   (3 children -> would trip BaseClassShouldBeAbstract
                            if Base were seen as concrete) *)
  let nodes = [
    mk S.Class "Base" 1  [("abstract","true")];
    mk S.Def "render" 2  [("abstract","true")];
    mk S.Def "priority" 3 [("abstract","true")];

    mk S.Class "A" 6 [("parent","Base")];
    mk S.Def "render" 7 [];
    mk S.Def "priority" 8 [];

    mk S.Class "B" 11 [("parent","Base")];
    mk S.Def "render" 12 [];
    mk S.Def "priority" 13 [];

    mk S.Class "C" 16 [("parent","Base")];
    mk S.Def "render" 17 [];
    mk S.Def "priority" 18 [];
  ] in

  let config = Catseye_claws.Types.default_config in
  let findings = Catseye_claws.Hierarchy_smells.analyze nodes config in

  Stdlib.Printf.printf "hierarchy_abstract_test: %d findings\n" (Stdlib.List.length findings);
  Stdlib.List.iter (fun (f : Catseye_types.Finding.t) ->
    Stdlib.Printf.printf "  [%s] %s:%d %s\n" f.rule f.file f.line f.message
  ) findings;

  let has rule =
    Stdlib.List.exists (fun (f : Catseye_types.Finding.t) -> f.rule = rule) findings
  in

  (* An abstract base with 3 children must NOT be flagged as needing to be
     abstract - it already is. *)
  assert (not (has "BaseClassShouldBeAbstract"));

  (* Overrides that fulfill an `abstract def` contract are polymorphism,
     not refused bequest. *)
  let refused =
    Stdlib.List.filter (fun (f : Catseye_types.Finding.t) -> f.rule = "RefusedParentBequest") findings
  in
  assert (refused = []);

  (* BaseClassKnowsDerivedClass is deliberately NOT touched by this change:
     it fires on child-count alone. Asserting it here documents that the
     abstract-awareness fix does not affect it, and makes the test's sole
     finding self-explaining in CI output. *)
  assert (has "BaseClassKnowsDerivedClass");

  Stdlib.Printf.printf "OK: abstract base and contract-fulfilling overrides not flagged\n"
