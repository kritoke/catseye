(* lib/catseye_claws/dry_ast.ml
   AST-native DRY violation detector via subtree hashing.

   Replaces the flat engine's sliding-window approach (dry.ml) with
   structural hashing on CatseyeAST.t expression trees.

   Advantages over flat engine:
   - Exact subtree boundaries (not line-range heuristics)
   - Understands nesting structure (EBlock, ELet, EIf branches)
   - Skips language boilerplate (imports, accessors) by construction
   - Cross-file comparison via canonical hash

   Algorithm:
   1. WALK    — extract function body subtrees (EBlock children, ELet bodies)
   2. NORM    — canonicalize each subtree (strip var names, preserve call names)
   3. HASH    — structural hash of canonical form
   4. BUCKET  — group subtrees by hash
   5. REPORT  — buckets with >= min_occurrences across >= 2 files are violations
*)

open Base

(* String comparisons use Stdlib explicitly since Base remaps = and <> *)
let (=) = Stdlib.( = )
let (<>) = Stdlib.( <> )

open Catseye_ast.Types

(* ── Canonical representation ───────────────────────────────────────── *)

(** Produce a canonical string for an expression subtree.
    Variable names are stripped (catches copy-paste-with-rename).
    Function call names are preserved (API patterns matter).
    Literals are normalized to their type. *)
let rec canonicalize (e : expr) : string =
  match e.expr_value with
  | EUnit -> "U"
  | ELiteral lit ->
    (match lit with
     | LInt _ -> "Li"
     | LFloat _ -> "Lf"
     | LString _ -> "Ls"
     | LBool _ -> "Lb"
     | LChar _ -> "Lc"
     | LUnit -> "Lu"
     | LNull -> "Ln")
  | EVar _ -> "V"  (* strip name *)
  | EFieldAccess (e, field) ->
    Stdlib.Printf.sprintf "F(%s,%s)" (canonicalize e) field
  | ETuple es ->
    Stdlib.Printf.sprintf "T(%s)" (canon_list es)
  | EList es ->
    Stdlib.Printf.sprintf "L[%s]" (canon_list es)
  | ERecord fields ->
    let entries = Stdlib.List.map (fun (k, v) ->
      Stdlib.Printf.sprintf "%s=%s" k (canonicalize v)
    ) fields in
    Stdlib.Printf.sprintf "R{%s}" (Stdlib.String.concat ";" entries)
  | ERecordUpdate (e, fields) ->
    let entries = Stdlib.List.map (fun (k, v) ->
      Stdlib.Printf.sprintf "%s=%s" k (canonicalize v)
    ) fields in
    Stdlib.Printf.sprintf "RU(%s,{%s})" (canonicalize e) (Stdlib.String.concat ";" entries)
  | EApp (fn, args) ->
    (* Preserve call target name — it matters for API patterns *)
    let fn_name = match fn.expr_value with
      | EVar name -> name
      | EFieldAccess (_, field) -> field
      | _ -> "_"
    in
    Stdlib.Printf.sprintf "A(%s,%s)" fn_name (canon_list args)
  | EFn _ -> "Fn"  (* closures normalized away *)
  | EIf (cond, then_e, else_opt) ->
    Stdlib.Printf.sprintf "I(%s,%s%s)"
      (canonicalize cond)
      (canonicalize then_e)
      (match else_opt with Some e -> "," ^ canonicalize e | None -> "")
  | ECase (target, branches) ->
    let brs = Stdlib.List.map (fun (_, body) -> canonicalize body) branches in
    Stdlib.Printf.sprintf "C(%s,[%s])" (canonicalize target) (Stdlib.String.concat ";" brs)
  | ELet (_, e1, e2) ->
    Stdlib.Printf.sprintf "Le(%s,%s)" (canonicalize e1) (canonicalize e2)
  | ELetAssert (_, e1, e2) ->
    Stdlib.Printf.sprintf "La(%s,%s)" (canonicalize e1) (canonicalize e2)
  | EAssignment (e1, e2) ->
    Stdlib.Printf.sprintf "As(%s,%s)" (canonicalize e1) (canonicalize e2)
  | EBinOp (e1, op, e2) ->
    Stdlib.Printf.sprintf "B(%s,%s,%s)" (canonicalize e1) op (canonicalize e2)
  | EUnOp (op, e) ->
    Stdlib.Printf.sprintf "Uo(%s,%s)" op (canonicalize e)
  | EBlock es ->
    Stdlib.Printf.sprintf "Bl[%s]" (canon_list es)
  | EError _ -> "Err"
  | EUnknown _ | ETryCatchFinally _ | EUse _ -> "Unk"

and canon_list (es : expr list) : string =
  Stdlib.String.concat "," (Stdlib.List.map canonicalize es)

(* ── Subtree extraction ─────────────────────────────────────────────── *)

(** A subtree with location info for reporting *)
type subtree = {
  file : string;
  lang : string;
  line : int;
  end_line : int;
  expr : expr;
  canon : string;
  hash : string;
}

(** Minimum subtree size (in canonical string length) to consider.
    Tiny subtrees (single vars, literals, small expressions) are not
    meaningful duplicates. 40 chars ≈ 3–4 nodes in a pattern. *)
let min_subtree_size = 40

(** Maximum subtree depth to extract — avoids hashing entire function bodies.
    We mostly care about statement-level duplication in EBlock children. *)
let max_depth = 4

(** Check if a subtree is worth extracting for DRY comparison.
    Skip trivial patterns: single variables, single literals, empty blocks,
    and very short canonical forms that match too broadly. *)
let is_interesting_subtree (canon : string) : bool =
  Stdlib.String.length canon >= min_subtree_size
  (* Must contain at least one function call — pure data patterns are noise *)
  && (let rec has_call c =
        Stdlib.String.length c >= 2 &&
        (Stdlib.String.sub c 0 2 = "A(" || (* EApp *)
         Stdlib.String.length c >= 3 &&
         (Stdlib.String.sub c 0 3 = "Le(" || (* ELet — let bindings are structural *)
          Stdlib.String.sub c 0 3 = "I(," || (* EIf — conditional logic is structural *)
          (* Recurse into nested structures *)
          let inner = try Stdlib.String.sub c 2 (Stdlib.String.length c - 3) with _ -> "" in
          has_call inner))
      in has_call canon)

(** Extract subtrees from an expression up to a given depth.
    We extract at statement boundaries (EBlock children, ELet bodies)
    rather than every sub-expression to reduce noise. *)
let rec extract_subtrees (e : expr) (file : string) (lang : string) (depth : int)
    : subtree list =
  if depth > max_depth then []
  else begin
    let canon = canonicalize e in
    let self =
      if is_interesting_subtree canon then
        Some {
          file; lang;
          line = e.expr_location.start.line;
          end_line = e.expr_location.end_.line;
          expr = e; canon;
          hash = Stdlib.Printf.sprintf "%08x" (Stdlib.Hashtbl.hash canon);
        }
      else None
    in
    (* Recurse into child expressions *)
    let children = match e.expr_value with
      | EBlock es ->
        (* Extract each statement in the block as a separate subtree *)
        Stdlib.List.concat_map (fun child ->
          extract_subtrees child file lang (depth + 1)
        ) es
      | ELet (_, e1, e2) ->
        extract_subtrees e1 file lang (depth + 1)
        @ extract_subtrees e2 file lang (depth + 1)
      | ELetAssert (_, e1, e2) ->
        extract_subtrees e1 file lang (depth + 1)
        @ extract_subtrees e2 file lang (depth + 1)
      | EIf (cond, then_e, else_opt) ->
        extract_subtrees cond file lang (depth + 1)
        @ extract_subtrees then_e file lang (depth + 1)
        @ (match else_opt with
           | Some e -> extract_subtrees e file lang (depth + 1)
           | None -> [])
      | ECase (_, branches) ->
        Stdlib.List.concat_map (fun (_, body) ->
          extract_subtrees body file lang (depth + 1)
        ) branches
      | EAssignment (e1, e2) ->
        extract_subtrees e1 file lang (depth + 1)
        @ extract_subtrees e2 file lang (depth + 1)
      | EBinOp (e1, _, e2) ->
        extract_subtrees e1 file lang (depth + 1)
        @ extract_subtrees e2 file lang (depth + 1)
      | EApp (fn, args) ->
        extract_subtrees fn file lang (depth + 1)
        @ Stdlib.List.concat_map (fun a ->
          extract_subtrees a file lang (depth + 1)
        ) args
      | ETuple es | EList es ->
        Stdlib.List.concat_map (fun child ->
          extract_subtrees child file lang (depth + 1)
        ) es
      | ERecord fields ->
        Stdlib.List.concat_map (fun (_, v) ->
          extract_subtrees v file lang (depth + 1)
        ) fields
      | ERecordUpdate (e, fields) ->
        extract_subtrees e file lang (depth + 1)
        @ Stdlib.List.concat_map (fun (_, v) ->
          extract_subtrees v file lang (depth + 1)
        ) fields
      | EFieldAccess (e, _) ->
        extract_subtrees e file lang (depth + 1)
      | EUnOp (_, e) ->
        extract_subtrees e file lang (depth + 1)
      | EFn (_, body) ->
        extract_subtrees body file lang (depth + 1)
      | _ -> []
    in
    match self with
    | Some s -> s :: children
    | None -> children
  end

(* ── Deduplication ──────────────────────────────────────────────────── *)

(** Remove subtrees at the same (file, line) location. *)
let unique_by_location (subtrees : subtree list) : subtree list =
  let seen = Stdlib.Hashtbl.create 32 in
  Stdlib.List.filter (fun (s : subtree) ->
    let key = Stdlib.Printf.sprintf "%s:%d" s.file s.line in
    if Stdlib.Hashtbl.mem seen key then false
    else begin Stdlib.Hashtbl.add seen key true; true end
  ) subtrees

(* ── Finding construction ───────────────────────────────────────────── *)

let make_dry_finding (subtrees : subtree list) : Catseye_types.Finding.t =
  let count = Stdlib.List.length subtrees in
  let first = Stdlib.List.hd subtrees in
  let locations = Stdlib.List.map (fun (s : subtree) ->
    { Catseye_types.Finding.file = s.file; line = s.line
    ; message = Stdlib.Printf.sprintf "Duplicate block (lines %d-%d)" s.line s.end_line
    }
  ) subtrees in
  { Catseye_types.Finding.rule = "DRYViolation"
  ; severity = "Medium"
  ; file = first.file
  ; line = first.line
  ; message = Stdlib.Printf.sprintf
      "Duplicate code block found in %d location(s) (consider extracting shared logic)"
      count
  ; flow = locations
  ; language = first.lang
  ; dependency = None
  ; reachability = None
  ; suggestion = None
  }

(* ── File exemptions ────────────────────────────────────────────────── *)

(** File patterns exempt from DRY checks.
    Constants tables, benchmarks, examples are inherently repetitive. *)
let is_dry_exempt_file = Scope.is_dry_exempt_file

(* ── Detection ──────────────────────────────────────────────────────── *)

(** Detect DRY violations from AST modules.
    Uses structural hashing on expression subtrees for precise detection. *)
let analyze (modules : Catseye_ast.Types.t list) (config : Types.claws_config)
    : Catseye_types.Finding.t list =
  if not config.dry_enabled then []
  else begin
    (* Build scopes to get function bodies *)
    let scopes = Ast_scope.build modules in
    (* Extract subtrees from all function bodies *)
    let all_subtrees = Stdlib.List.concat_map (fun (scope : Ast_scope.ast_scope) ->
      if is_dry_exempt_file scope.file then []
      else extract_subtrees scope.body scope.file scope.lang 0
    ) scopes in
    (* Bucket by hash *)
    let buckets : (string, subtree list) Stdlib.Hashtbl.t = Stdlib.Hashtbl.create 256 in
    Stdlib.List.iter (fun (s : subtree) ->
      let existing = try Stdlib.Hashtbl.find buckets s.hash with Stdlib.Not_found -> [] in
      Stdlib.Hashtbl.replace buckets s.hash (s :: existing)
    ) all_subtrees;
    (* Filter to violations: >= min_occurrences unique locations
       across at least 2 different files *)
    Stdlib.Hashtbl.fold (fun _hash (subtrees : subtree list) acc ->
      let unique = unique_by_location subtrees in
      let unique_files =
        Stdlib.List.fold_left (fun s (s2 : subtree) ->
          if Stdlib.List.mem s2.file s then s else s2.file :: s
        ) [] unique
      in
      if Stdlib.List.length unique >= config.dry_min_occurrences
         && Stdlib.List.length unique_files >= 2 then
        make_dry_finding unique :: acc
      else acc
    ) buckets []
  end