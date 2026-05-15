# Pi Extension: Catseye Security Scan

Install into any project that uses [pi](https://pi.dev):

```bash
# Copy to project-local extensions
mkdir -p .pi/extensions/catseye-scan
cp index.ts .pi/extensions/catseye-scan/

# Or install globally
mkdir -p ~/.pi/agent/extensions/catseye-scan
cp index.ts ~/.pi/agent/extensions/catseye-scan/
```

Requires `catseye-ocaml` binary and KDL rules directory. Auto-discovers from:
- Binary: `PATH`, `~/.local/bin/`, `/usr/local/bin/`, local `bin/`
- Rules: `~/.local/lib/catseye/rules/`, `/usr/local/lib/catseye/rules/`, local `src/ocaml/rules/`

Registers the `catseye_scan` tool that the LLM can call directly to scan a project directory.
