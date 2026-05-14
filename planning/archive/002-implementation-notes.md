# Implementation Notes — Initial Build

## What works
- Crystal extractor: parses .cr files using Crystal::Parser, outputs Security Node JSON
- Gleam engine: decodes JSON via Erlang FFI parser, runs SSRF + CommandInjection rules
- Full pipeline: Crystal → JSON → Erlang/Gleam → Findings JSON

## Key lessons
1. Crystal compiler internals need `CRYSTAL_HAS_WRAPPER=1` env var
2. `require "compiler/crystal/syntax"` is the correct require path
3. Gleam strings on BEAM are binaries (`<<"foo">>`), not charlists (`"foo"`)
4. Our hand-rolled JSON parser in Erlang FFI returns binaries for all string values
5. `list.contains` is the correct Gleam function (not `list.has`)
6. Gleam custom type constructors must be explicitly imported
7. Erlang entry point: `catseye:main()` with `-pa` for ebin dirs
8. `rebar3` is needed in the nix shell for Gleam Erlang target builds

## Detected findings in test samples
- vulnerable.cr: 2 SSRF (line 12, 19) + 1 CommandInjection (line 30)
- safe.cr: 0 findings (correct — all HTTP calls use literal URLs)
