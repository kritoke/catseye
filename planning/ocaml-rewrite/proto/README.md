# OCaml Rewrite Prototypes

This folder contains experimental prototypes for evaluating the OCaml rewrite feasibility.

## Structure

```
proto/
├── taint_db/     # TaintDB Map implementation prototype
├── graph/        # Vulnerability graph prototype  
└── cli/          # CLI skeleton prototype
```

## Running Prototypes

Prototypes are standalone OCaml files that can be run with:

```bash
cd planning/ocaml-rewrite/proto/<name>
opam install --deps-only -y .
dune exec <target>
```

## Purpose

These prototypes are for **evaluation only**. They:
- Test specific OCaml patterns before committing to full implementation
- Validate that OCaml can correctly implement current Gleam/Nim logic
- Provide benchmarks to compare against current system

Code here is not intended for production use.