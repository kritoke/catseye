# F# Extractor

F# source extractor for Catseye. Uses [F# Compiler Service](https://fsharp.github.io/fsharp-compiler-docs/fcs/) (FCS) to parse `.fs`, `.fsx`, and `.fsi` files and emit a typed AST as XML.

## Requirements

- .NET SDK 10.0+ (the nix dev shell provides this via `dotnetCorePackages.sdk_10_0`)
- FSharp.Compiler.Service 43.12.204 (pinned in the fsproj)

## Build

```bash
cd src/extractor/fsharp
dotnet build
```

## Usage

```bash
# Output to stdout
dotnet run -- path/to/file.fs

# Output to file
dotnet run -- path/to/file.fs --out output.xml
```

Exit codes:
- `0` — success
- `1` — I/O error (file not found, etc.)
- `2` — parse error (syntax errors in the F# source)

## Wire Format

The extractor emits XML with a root `<wire-format version="1">` element. Each AST node maps to an XML element with `srow`, `scol`, `erow`, `ecol` attributes (0-based rows and columns, matching the convention used by tree-sitter XML output in `catseye_ast/tree_sitter_xml.ml`).

See `tests/fixtures/fsharp/spike-output.xml` for a complete example.

### Node Types

| XML Element | F# AST Node | Notes |
|---|---|---|
| `module_or_namespace` | `SynModuleOrNamespace` | Top-level module/namespace |
| `open` | `SynModuleDecl.Open` | `open System.IO` |
| `type_defn` | `SynTypeDefn` | Record, union, or class |
| `binding` | `SynBinding` | `let` binding |
| `expr_app` | `SynExpr.App` | Function application |
| `expr_let` | `SynExpr.LetOrUse` | Let binding in expression |
| `expr_if` | `SynExpr.IfThenElse` | If/else |
| `expr_match` | `SynExpr.Match` | Match expression |
| `expr_lambda` | `SynExpr.Lambda` | Lambda/fun |
| `expr_foreach` | `SynExpr.ForEach` | For-in loop |
| `expr_computationexpr` | `SynExpr.ComputationExpr` | Computation expression (async, etc.) |
| `expr_record` | `SynExpr.Record` | Record construction |
| `expr_dotget` | `SynExpr.DotGet` | Property access |
| `expr_tuple` | `SynExpr.Tuple` | Tuple |
| `expr_list` | `SynExpr.ArrayOrList` | List literal |
| `expr_seq` | `SynExpr.Sequential` | Sequential expressions |
| `expr_longident` | `SynExpr.LongIdent` | Qualified identifier |
| `expr_ident` | `SynExpr.Ident` | Simple identifier |
| `expr_string/int/float/bool/unit` | `SynExpr.Const` | Literals |
| `pat_named/wild/tuple/longident` | `SynPat.*` | Patterns |
| `type_longident/fun/tuple/app` | `SynType.*` | Type annotations |

### Wire Format Versioning

The root element includes a `version` attribute. The OCaml mapper (`fsharp_mapper.ml`) refuses to consume a wire format with an unrecognized version. Bump the version on any breaking change to the XML schema.

## Architecture

The extractor follows the same pattern as the Crystal and Elixir extractors:
- Source lives in `src/extractor/fsharp/`
- Built on demand via `dotnet run` or `dotnet publish`
- NOT a nix derivation (like Crystal/Elixir extractors)
- The OCaml mapper shells out to the extractor binary via `Process.exec`

## Known Limitations

- `.fsx` files with `#load` directives are not supported (each file is parsed independently)
- Full type-checking is not performed (design decision 4); only the parse tree is emitted
- Type-provider-aware analysis is not in scope for the first slice
