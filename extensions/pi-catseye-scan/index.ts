import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

interface Finding {
  rule: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  flow: Array<{ file: string; line: number; message: string }>;
}

interface ScanResult {
  version: string;
  target: string;
  files_scanned: number;
  nodes_extracted: number;
  findings_count: number;
  findings: Finding[];
}

function findBinary(): string | null {
  const candidates = [
    "catseye-ocaml",
    join(process.env.HOME || "/root", ".local/bin/catseye-ocaml"),
    "/usr/local/bin/catseye-ocaml",
  ];

  for (const cmd of candidates) {
    try {
      const which = execSync(`which ${cmd} 2>/dev/null`, { encoding: "utf-8" }).trim();
      if (which) return which;
    } catch {}
  }

  // Check common build locations relative to cwd
  const localCandidates = [
    join("bin", "catseye-ocaml"),
    join("vendor", "catseye", "bin", "catseye-ocaml"),
  ];
  for (const p of localCandidates) {
    if (existsSync(p)) return resolve(p);
  }

  return null;
}

function findRules(): string | null {
  const candidates = [
    join(process.env.HOME || "/root", ".local/lib/catseye/rules"),
    "/usr/local/lib/catseye/rules",
    join("vendor", "catseye", "src/ocaml/rules"),
    join("src", "ocaml", "rules"),
  ];

  for (const dir of candidates) {
    if (existsSync(join(dir, "ssrf.kdl"))) return resolve(dir);
  }

  return null;
}

function findSourceDir(cwd: string): string | null {
  if (existsSync(join(cwd, "src"))) return join(cwd, "src");
  if (existsSync(join(cwd, "client", "src"))) return join(cwd, "client", "src");
  return null;
}

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "catseye_scan",
    label: "Catseye Security Scan",
    description:
      "Run Catseye static security scanner on the project. Detects SSRF, injection (SQL/command/path/LDAP), open redirects, hardcoded secrets, weak crypto, missing timeouts, ReDoS, and more via taint analysis on Crystal and Gleam code. Also detects code smells (complexity, god objects, deep nesting, long parameter lists) and AI antipatterns (hallucinated methods, hardcoded URLs). Returns structured findings with taint flow traces.",
    promptSnippet: "Scan for security vulnerabilities and code smells",
    promptGuidelines: [
      "Use catseye_scan when the user asks to scan for security issues, code quality, or antipatterns.",
      "After scanning, triage findings as Real/False Positive/Won't Fix before proposing fixes.",
      "The flat taint engine is used by default. Use cfg=true for branch-aware analysis (more findings).",
      "Common false positives: DeadCode on early-return guards, SSRF on hardcoded URLs, GodObject on cohesive domain classes.",
      "Sanitizer calls (File.expand_path, URI.parse, validate_*) automatically suppress downstream findings.",
    ],
    parameters: Type.Object({
      directory: Type.Optional(Type.String({
        description: "Directory to scan (defaults to src/ or client/src/)",
      })),
      rules_dir: Type.Optional(Type.String({
        description: "Path to KDL rules directory (auto-detected if omitted)",
      })),
      cfg: Type.Optional(Type.Boolean({
        description: "Use IL/CFG-based taint engine — more sensitive, branch-aware analysis (default: false)",
        default: false,
      })),
      ai_lint: Type.Optional(Type.Boolean({
        description: "Enable AI antipattern detection (default: true)",
        default: true,
      })),
      claws: Type.Optional(Type.Boolean({
        description: "Enable code smell detection (default: true)",
        default: true,
      })),
      claws_suppress: Type.Optional(Type.Array(Type.String({
        description: "Glob patterns for directories to suppress in Claws findings",
      })), {
        description: "Claws suppression patterns",
      }),
    }),

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const binary = findBinary();
      if (!binary) {
        return {
          content: [{
            type: "text",
            text: "Catseye binary not found. Install with: just install or add to PATH.",
          }],
          isError: true,
        };
      }

      const rules = params.rules_dir || findRules();
      if (!rules) {
        return {
          content: [{
            type: "text",
            text: "Catseye KDL rules not found. Set --rules_dir or install to ~/.local/lib/catseye/rules/",
          }],
          isError: true,
        };
      }

      const target = params.directory || findSourceDir(ctx.cwd) || ctx.cwd;

      const flags: string[] = [
        `--rules '${rules}'`,
        "--format json",
      ];
      if (params.cfg) flags.push("--cfg");
      if (params.ai_lint !== false) flags.push("--ai-lint");
      if (params.claws !== false) flags.push("--claws");

      const cmd = `${binary} ${flags.join(" ")} '${target}' 2>/dev/null`;

      let stdout: string;
      try {
        stdout = execSync(cmd, {
          encoding: "utf-8",
          maxBuffer: 50 * 1024 * 1024,
          timeout: 120_000,
          cwd: ctx.cwd,
        });
      } catch (err: any) {
        return {
          content: [{
            type: "text",
            text: `Scan failed: ${err.message}`,
          }],
          isError: true,
        };
      }

      let result: ScanResult;
      try {
        // Extract first valid JSON object from output
        const start = stdout.indexOf("{");
        if (start === -1) throw new Error("No JSON found");
        let depth = 0;
        let end = start;
        for (let i = start; i < stdout.length; i++) {
          if (stdout[i] === "{") depth++;
          else if (stdout[i] === "}") depth--;
          if (depth === 0) { end = i + 1; break; }
        }
        result = JSON.parse(stdout.slice(start, end));
      } catch {
        return {
          content: [{
            type: "text",
            text: `Failed to parse scan output. Raw output:\n${stdout.slice(0, 2000)}`,
          }],
          isError: true,
        };
      }

      const findings = result.findings || [];
      const errors = findings.filter((f) => f.severity === "High" || f.severity === "Critical").length;
      const warnings = findings.filter((f) => f.severity === "Medium" || f.severity === "Low").length;

      // Group by rule
      const byRule: Record<string, number> = {};
      for (const f of findings) {
        byRule[f.rule] = (byRule[f.rule] || 0) + 1;
      }

      const summary = [
        `**Catseye v${result.version} scan complete**`,
        `Files: ${result.files_scanned} | Nodes: ${result.nodes_extracted}`,
        `Findings: ${errors} errors, ${warnings} warnings`,
        params.cfg ? "Engine: CFG (branch-aware)" : "Engine: flat (default)",
        "",
        "By rule:",
        ...Object.entries(byRule)
          .sort(([, a], [, b]) => b - a)
          .map(([rule, count]) => `  ${rule}: ${count}`),
        "",
        "---",
        "",
        "## Findings",
        "",
        ...findings.map((f) => {
          const icon = f.severity === "High" || f.severity === "Critical" ? "🔴" : "⚠️";
          const file = f.file.replace(ctx.cwd + "/", "");
          const flow = f.flow && f.flow.length > 0
            ? `\n  ← ${f.flow.map((s) => `${s.message} (${file}:${s.line})`).join(" ← ")}`
            : "";
          return `${icon} **${f.rule}** \`${file}:${f.line}\` — ${f.message}${flow}`;
        }),
      ].join("\n");

      return {
        content: [{ type: "text", text: summary }],
        details: {
          version: result.version,
          files_scanned: result.files_scanned,
          errors,
          warnings,
          engine: params.cfg ? "cfg" : "flat",
          findings: findings.map((f) => ({
            rule: f.rule,
            severity: f.severity,
            file: f.file,
            line: f.line,
            message: f.message,
          })),
        },
      };
    },
  });
}
