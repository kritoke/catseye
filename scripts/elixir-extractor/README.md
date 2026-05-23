# CatseyeExtractor

A Mix task that extracts AST information from Elixir codebases for Catseye analysis.

## Usage

```bash
# Run on the current project
mix run -e "CatseyeExtractor.run"

# Run on a specific file
mix run -e "CatseyeExtractor.run_file(\"lib/foo.ex\")"

# Run on a specific directory
mix run -e "CatseyeExtractor.run_dir(\"lib\")"
```

## Output Format

Outputs JSON (one object per line) compatible with Catseye's AST representation:

```json
{
  "file": "lib/foo/bar.ex",
  "language": "elixir",
  "module": "Foo.Bar",
  "functions": [
    {
      "name": "my_function",
      "arity": 2,
      "params": ["arg1", "arg2"],
      "line": 10,
      "calls": [{ "name": "HTTPoison.get", "line": 15, "args": ["url"] }],
      "sinks": ["HTTPoison.get"],
      "sources": ["conn.params"],
      "raw_ast": "..."
    }
  ]
}
```

## Key Patterns Detected

### SSRF Sinks

- `HTTPoison.get/1,2`, `HTTPoison.post/1,2`, etc.
- `Tesla.get/2`, `Tesla.post/2`, etc.
- `Req.get/1`, `Req.post/1`, etc.
- `Mint.HTTP.connect/1`

### SQL Injection Sinks

- `Ecto.Repo.all/1`
- `Repo.all/1`, `Repo.query/1`
- `Ecto.Adapters.SQL.query/2`

### XSS Sinks

- `Phoenix.HTML.raw/1`
- `content_tag/3` with `raw: true`

### Code Execution Sinks

- `Code.eval_string/1`
- `Code.eval/2`
- `Kernel.eval/2`

### Sources

- `conn.params`
- `conn.body`
- `conn.query_params`
- `conn.path_params`
- `params["key"]`

### Anti-patterns

- `rescue _` (blanket rescue)
- `String.to_atom/1` (unsafe atom conversion)
- `File.rm_rf/1` (dangerous file deletion)
