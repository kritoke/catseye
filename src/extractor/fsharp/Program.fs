// FCS spike — parse an F# file, walk the untyped AST, emit XML wire format
// Confirms we can reach: SynModuleDecl, SynBinding, SynPat, SynExpr, SynType
// Target: FSharp.Compiler.Service 43.12.204 on .NET 10
//
// Wire format: XML with root <wire-format version="1">.
// Each AST node maps to an XML element with srow/scol/erow/ecol attributes.
// This is the canonical format the OCaml mapper (fsharp_mapper.ml) will consume.

open System
open System.IO
open System.Text
open FSharp.Compiler.CodeAnalysis
open FSharp.Compiler.Text
open FSharp.Compiler.Syntax
open FSharp.Compiler.Diagnostics

// ── helpers ────────────────────────────────────────────────────

// NOTE: sb is module-level mutable state. This is acceptable because the
// extractor is a single-shot CLI tool (one parse per process invocation).
// If the extractor is ever embedded in a larger application, sb should be
// passed through the walk functions as a parameter.
let sb = StringBuilder()
let indent depth = String(' ', depth * 2)
let xmlEscape (s: string) =
    s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
        .Replace("\"", "&quot;").Replace("'", "&apos;")
let rangeToAttrs (r: range) =
    sprintf "srow=\"%d\" scol=\"%d\" erow=\"%d\" ecol=\"%d\""
        (r.StartLine - 1) r.StartColumn (r.EndLine - 1) r.EndColumn
let emitOpen tag attrs depth = sb.AppendLine(sprintf "%s<%s %s>" (indent depth) tag attrs) |> ignore
let emitSelfClosing tag attrs depth = sb.AppendLine(sprintf "%s<%s %s/>" (indent depth) tag attrs) |> ignore
let emitClose tag depth = sb.AppendLine(sprintf "%s</%s>" (indent depth) tag) |> ignore
let emitText tag text attrs depth = sb.AppendLine(sprintf "%s<%s %s>%s</%s>" (indent depth) tag attrs (xmlEscape text) tag) |> ignore

let idsToName (ids: Ident list) = ids |> List.map (fun i -> i.idText) |> String.concat "."
let lidToName (SynLongIdent(id = ids)) = idsToName ids

// ── walk the AST ──────────────────────────────────────────────

let rec walkSynType (ty: SynType) depth =
    let r = rangeToAttrs ty.Range
    match ty with
    | SynType.LongIdent(lid) -> emitText "type_longident" (lidToName lid) r depth
    | SynType.App(typeName = ty; typeArgs = args) ->
        emitOpen "type_app" r depth
        walkSynType ty (depth + 1)
        for a in args do walkSynType a (depth + 1)
        emitClose "type_app" depth
    | SynType.Fun(argType = arg; returnType = ret) ->
        emitOpen "type_fun" r depth
        walkSynType arg (depth + 1)
        walkSynType ret (depth + 1)
        emitClose "type_fun" depth
    | SynType.Tuple(path = segments) ->
        emitOpen "type_tuple" r depth
        for seg in segments do match seg with SynTupleTypeSegment.Type(ty) -> walkSynType ty (depth + 1) | _ -> ()
        emitClose "type_tuple" depth
    | SynType.Anon _ -> emitSelfClosing "type_anon" r depth
    | _ -> emitSelfClosing "type_unknown" r depth

let rec walkSynPat (pat: SynPat) depth =
    let r = rangeToAttrs pat.Range
    match pat with
    | SynPat.Named(SynIdent(ident, _), _, _, _) -> emitText "pat_named" ident.idText r depth
    | SynPat.Wild _ -> emitSelfClosing "pat_wild" r depth
    | SynPat.Const(constant = SynConst.String(text = s)) -> emitText "pat_string" s r depth
    | SynPat.Const(constant = SynConst.Int32(n)) -> emitText "pat_int" (string n) r depth
    | SynPat.Const(constant = SynConst.Bool(b)) -> emitText "pat_bool" (string b) r depth
    | SynPat.Const(constant = SynConst.Unit) -> emitSelfClosing "pat_unit" r depth
    | SynPat.Tuple(_, pats, _, _) ->
        emitOpen "pat_tuple" r depth
        for p in pats do walkSynPat p (depth + 1)
        emitClose "pat_tuple" depth
    | SynPat.ListCons(lhs, rhs, _, _) ->
        emitOpen "pat_listcons" r depth
        walkSynPat lhs (depth + 1); walkSynPat rhs (depth + 1)
        emitClose "pat_listcons" depth
    | SynPat.Paren(pat = p) -> walkSynPat p depth
    | SynPat.Attrib(pat = p) -> walkSynPat p depth
    | SynPat.Typed(pat = p; targetType = ty) ->
        emitOpen "pat_typed" r depth
        walkSynPat p (depth + 1); walkSynType ty (depth + 1)
        emitClose "pat_typed" depth
    | SynPat.LongIdent(longDotId = lid; argPats = args) ->
        emitOpen ("pat_longident name=\"" + lidToName lid + "\"") r depth
        (match args with
         | SynArgPats.Pats(ps) -> for p in ps do walkSynPat p (depth + 1)
         | _ -> ())
        emitClose "pat_longident" depth
    | _ -> emitSelfClosing "pat_unknown" r depth

let rec walkSynExpr (expr: SynExpr) depth =
    let r = rangeToAttrs expr.Range
    match expr with
    | SynExpr.Const(constant = SynConst.String(text = s)) -> emitText "expr_string" s r depth
    | SynExpr.Const(constant = SynConst.Int32(n)) -> emitText "expr_int" (string n) r depth
    | SynExpr.Const(constant = SynConst.Bool(b)) -> emitText "expr_bool" (string b) r depth
    | SynExpr.Const(constant = SynConst.Unit) -> emitSelfClosing "expr_unit" r depth
    | SynExpr.Const(constant = SynConst.Double(d)) -> emitText "expr_float" (string d) r depth
    | SynExpr.Null _ -> emitSelfClosing "expr_null" r depth
    | SynExpr.Ident(id) -> emitText "expr_ident" id.idText r depth
    | SynExpr.LongIdent(longDotId = lid) -> emitText "expr_longident" (lidToName lid) r depth
    | SynExpr.App(isInfix = isInfix; funcExpr = func; argExpr = arg) ->
        emitOpen (sprintf "expr_app isInfix=\"%b\"" isInfix) r depth
        walkSynExpr func (depth + 1); walkSynExpr arg (depth + 1)
        emitClose "expr_app" depth
    | SynExpr.LetOrUse(lu) ->
        emitOpen "expr_let" r depth
        for b in lu.Bindings do walkSynBinding b (depth + 1)
        walkSynExpr lu.Body (depth + 1)
        emitClose "expr_let" depth
    | SynExpr.IfThenElse(ifExpr = cond; thenExpr = thenE; elseExpr = elseE) ->
        emitOpen "expr_if" r depth
        walkSynExpr cond (depth + 1); walkSynExpr thenE (depth + 1)
        (match elseE with Some e -> walkSynExpr e (depth + 1) | None -> ())
        emitClose "expr_if" depth
    | SynExpr.Match(expr = scrutinee; clauses = clauses) ->
        emitOpen "expr_match" r depth
        walkSynExpr scrutinee (depth + 1)
        for (SynMatchClause(pat = pat; resultExpr = body)) in clauses do
            emitOpen "match_clause" (rangeToAttrs body.Range) (depth + 1)
            walkSynPat pat (depth + 2); walkSynExpr body (depth + 2)
            emitClose "match_clause" (depth + 1)
        emitClose "expr_match" depth
    | SynExpr.TryWith(tryExpr = tryE; withCases = clauses) ->
        emitOpen "expr_trywith" r depth
        walkSynExpr tryE (depth + 1)
        for (SynMatchClause(pat = pat; resultExpr = body)) in clauses do
            emitOpen "catch_clause" (rangeToAttrs body.Range) (depth + 1)
            walkSynPat pat (depth + 2); walkSynExpr body (depth + 2)
            emitClose "catch_clause" (depth + 1)
        emitClose "expr_trywith" depth
    | SynExpr.Tuple(exprs = exprs) ->
        emitOpen "expr_tuple" r depth
        for e in exprs do walkSynExpr e (depth + 1)
        emitClose "expr_tuple" depth
    | SynExpr.ArrayOrList(exprs = exprs) ->
        emitOpen "expr_list" r depth
        for e in exprs do walkSynExpr e (depth + 1)
        emitClose "expr_list" depth
    | SynExpr.Record(recordFields = fields) ->
        emitOpen "expr_record" r depth
        for (SynExprRecordField(fieldName = (lid, _); expr = exprOpt)) in fields do
            match exprOpt with
            | Some expr ->
                emitOpen ("record_field name=\"" + lidToName lid + "\"") (rangeToAttrs expr.Range) (depth + 1)
                walkSynExpr expr (depth + 2)
                emitClose "record_field" (depth + 1)
            | None -> ()
        emitClose "expr_record" depth
    | SynExpr.DotGet(longDotId = lid; expr = obj) ->
        emitOpen ("expr_dotget field=\"" + lidToName lid + "\"") r depth
        walkSynExpr obj (depth + 1)
        emitClose "expr_dotget" depth
    | SynExpr.DotSet(targetExpr = obj; longDotId = lid; rhsExpr = value) ->
        emitOpen ("expr_dotset field=\"" + lidToName lid + "\"") r depth
        walkSynExpr obj (depth + 1); walkSynExpr value (depth + 1)
        emitClose "expr_dotset" depth
    | SynExpr.Sequential(expr1 = e1; expr2 = e2) ->
        emitOpen "expr_seq" r depth
        walkSynExpr e1 (depth + 1); walkSynExpr e2 (depth + 1)
        emitClose "expr_seq" depth
    | SynExpr.Lambda(body = body) ->
        emitOpen "expr_lambda" r depth
        walkSynExpr body (depth + 1)
        emitClose "expr_lambda" depth
    | SynExpr.Do(expr = body) ->
        emitOpen "expr_do" r depth
        walkSynExpr body (depth + 1)
        emitClose "expr_do" depth
    | SynExpr.While(whileExpr = cond; doExpr = body) ->
        emitOpen "expr_while" r depth
        walkSynExpr cond (depth + 1); walkSynExpr body (depth + 1)
        emitClose "expr_while" depth
    | SynExpr.For(ident = id; doBody = body) ->
        emitOpen ("expr_for var=\"" + id.idText + "\"") r depth
        walkSynExpr body (depth + 1)
        emitClose "expr_for" depth
    | SynExpr.ForEach(pat = pat; enumExpr = enumE; bodyExpr = bodyE) ->
        emitOpen "expr_foreach" r depth
        walkSynPat pat (depth + 1); walkSynExpr enumE (depth + 1); walkSynExpr bodyE (depth + 1)
        emitClose "expr_foreach" depth
    | SynExpr.ComputationExpr(expr = e) ->
        emitOpen "expr_computationexpr" r depth
        walkSynExpr e (depth + 1)
        emitClose "expr_computationexpr" depth
    | SynExpr.YieldOrReturn(expr = e) ->
        emitOpen "expr_yieldorreturn" r depth
        walkSynExpr e (depth + 1)
        emitClose "expr_yieldorreturn" depth
    | SynExpr.Paren(expr = e) -> walkSynExpr e depth
    | SynExpr.Downcast(expr = e) | SynExpr.Upcast(expr = e) -> walkSynExpr e depth
    | SynExpr.InferredDowncast(expr = e) | SynExpr.InferredUpcast(expr = e) -> walkSynExpr e depth
    | SynExpr.Assert(expr = e) ->
        emitOpen "expr_assert" r depth
        walkSynExpr e (depth + 1)
        emitClose "expr_assert" depth
    | SynExpr.TypeApp(expr = e; typeArgs = types) ->
        emitOpen "expr_typeapp" r depth
        walkSynExpr e (depth + 1)
        for ty in types do walkSynType ty (depth + 1)
        emitClose "expr_typeapp" depth
    | SynExpr.New(targetType = ty; expr = arg) ->
        emitOpen "expr_new" r depth
        walkSynType ty (depth + 1); walkSynExpr arg (depth + 1)
        emitClose "expr_new" depth
    | SynExpr.TypeTest(expr = e; targetType = ty) ->
        emitOpen "expr_typetest" r depth
        walkSynExpr e (depth + 1); walkSynType ty (depth + 1)
        emitClose "expr_typetest" depth
    | SynExpr.Quote(quotedExpr = e) ->
        emitOpen "expr_quote" r depth
        walkSynExpr e (depth + 1)
        emitClose "expr_quote" depth
    | _ -> emitSelfClosing "expr_unknown" r depth

and walkSynBinding (b: SynBinding) depth =
    let (SynBinding(headPat = pat; expr = body; returnInfo = retTy)) = b
    let r = rangeToAttrs b.RangeOfBindingWithRhs
    emitOpen "binding" r depth
    walkSynPat pat (depth + 1)
    (match retTy with
     | Some(SynBindingReturnInfo(typeName = ty)) ->
         emitOpen "return_type" (rangeToAttrs ty.Range) (depth + 1)
         walkSynType ty (depth + 2)
         emitClose "return_type" (depth + 1)
     | None -> ())
    walkSynExpr body (depth + 1)
    emitClose "binding" depth

let walkSynTypeDefn (defn: SynTypeDefn) depth =
    let (SynTypeDefn(typeInfo = info; typeRepr = repr; members = members)) = defn
    let (SynComponentInfo(longId = ids)) = info
    let name = idsToName ids
    let r = rangeToAttrs defn.Range
    emitOpen ("type_defn name=\"" + name + "\"") r depth
    (match repr with
     | SynTypeDefnRepr.Simple(simpleRepr = SynTypeDefnSimpleRepr.Record(recordFields = fields)) ->
         emitOpen "record_repr" (rangeToAttrs repr.Range) (depth + 1)
         for (SynField(idOpt = idOpt; fieldType = ty)) in fields do
             let fname = idOpt |> Option.map (fun i -> i.idText) |> Option.defaultValue "_"
             emitOpen ("field name=\"" + fname + "\"") (rangeToAttrs ty.Range) (depth + 2)
             walkSynType ty (depth + 3)
             emitClose "field" (depth + 2)
         emitClose "record_repr" (depth + 1)
     | SynTypeDefnRepr.Simple(simpleRepr = SynTypeDefnSimpleRepr.Union(unionCases = cases)) ->
         emitOpen "union_repr" (rangeToAttrs repr.Range) (depth + 1)
         for (SynUnionCase(ident = SynIdent(id, _); caseType = caseType)) in cases do
             let caseR = rangeToAttrs id.idRange
             (match caseType with
              | SynUnionCaseKind.Fields(fields) ->
                  emitOpen ("union_case name=\"" + id.idText + "\"") caseR (depth + 2)
                  for (SynField(idOpt = fId; fieldType = ty)) in fields do
                      let fname = fId |> Option.map (fun i -> i.idText) |> Option.defaultValue "_"
                      emitOpen ("field name=\"" + fname + "\"") (rangeToAttrs ty.Range) (depth + 3)
                      walkSynType ty (depth + 4)
                      emitClose "field" (depth + 3)
                  emitClose "union_case" (depth + 2)
              | _ -> emitSelfClosing ("union_case name=\"" + id.idText + "\"") caseR (depth + 2))
         emitClose "union_repr" (depth + 1)
     | _ -> emitSelfClosing "type_repr_other" (rangeToAttrs repr.Range) (depth + 1))
    for m in members do match m with SynMemberDefn.Member(memberDefn = b) -> walkSynBinding b (depth + 1) | _ -> ()
    emitClose "type_defn" depth

let walkSynModuleDecl (decl: SynModuleDecl) depth =
    match decl with
    | SynModuleDecl.Let(bindings = bindings) -> for b in bindings do walkSynBinding b depth
    | SynModuleDecl.Types(typeDefns = defns) -> for d in defns do walkSynTypeDefn d depth
    | SynModuleDecl.Expr(expr = expr) -> walkSynExpr expr depth
    | SynModuleDecl.Open(target = target; range = r) ->
        (match target with
         | SynOpenDeclTarget.ModuleOrNamespace(longId = lid) ->
             emitText "open" (lidToName lid) (rangeToAttrs r) depth
         | _ -> ())
    | SynModuleDecl.Exception(range = r) -> emitSelfClosing "exception_decl" (rangeToAttrs r) depth
    | _ -> emitSelfClosing "module_decl_unknown" (rangeToAttrs decl.Range) depth

let walkModuleOrNamespace (modul: SynModuleOrNamespace) depth =
    let (SynModuleOrNamespace(longId = ids; decls = decls; kind = kind)) = modul
    let name = idsToName ids
    let kindStr =
        match kind with
        | SynModuleOrNamespaceKind.NamedModule -> "module"
        | SynModuleOrNamespaceKind.AnonModule -> "anon_module"
        | SynModuleOrNamespaceKind.DeclaredNamespace -> "namespace"
        | SynModuleOrNamespaceKind.GlobalNamespace -> "global"
    let r = rangeToAttrs modul.Range
    emitOpen (sprintf "module_or_namespace kind=\"%s\" name=\"%s\"" kindStr name) r depth
    for decl in decls do walkSynModuleDecl decl (depth + 1)
    emitClose "module_or_namespace" depth

// ── main ──────────────────────────────────────────────────────

[<EntryPoint>]
let main argv =
    if argv.Length < 1 then
        eprintfn "Usage: fcs-spike <file.fs> [--out <path>]"
        exit 2
    let filePath = argv.[0]
    let outPath = if argv.Length >= 3 && argv.[1] = "--out" then Some argv.[2] else None
    if not (IO.File.Exists filePath) then
        eprintfn "error: file not found: %s" filePath
        exit 1
    let sourceText = IO.File.ReadAllText filePath |> SourceText.ofString
    let parsingOptions = { FSharpParsingOptions.Default with SourceFiles = [| filePath |] }
    let checker = FSharpChecker.Create()
    let parseResults =
        try
            checker.ParseFile(filePath, sourceText, parsingOptions) |> fun a -> Async.RunSynchronously(a, timeout = 30000)
        with :? TimeoutException ->
            eprintfn "error: FCS parse timed out after 30s for %s" filePath
            exit 2
    let diags = parseResults.Diagnostics
    let hasErrors = diags |> Array.exists (fun d -> d.Severity = FSharpDiagnosticSeverity.Error)
    if hasErrors then
        for d in diags do
            eprintfn "%s(%d,%d): error: %s" d.FileName d.StartLine d.StartColumn d.Message
        exit 2
    sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>") |> ignore
    sb.AppendLine("<wire-format version=\"1\">") |> ignore
    (match parseResults.ParseTree with
     | ParsedInput.ImplFile(implFile) ->
         let (ParsedImplFileInput(contents = modules)) = implFile
         for m in modules do walkModuleOrNamespace m 1
     | ParsedInput.SigFile(sigFile) ->
         let (ParsedSigFileInput(contents = modules)) = sigFile
         for m in modules do
             let (SynModuleOrNamespaceSig(longId = ids)) = m
             emitOpen (sprintf "module_sig name=\"%s\"" (idsToName ids)) (rangeToAttrs m.Range) 1
             emitClose "module_sig" 1)
    sb.AppendLine("</wire-format>") |> ignore
    let output = sb.ToString()
    match outPath with
    | Some p -> IO.File.WriteAllText(p, output)
    | None -> printf "%s" output
    0
