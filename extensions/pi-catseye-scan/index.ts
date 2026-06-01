import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { spawnSync } from "node:child_process";
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

function findBinary(cwd: string): string | null {
	// Prefer local build in the project (always freshest)
	const localCandidates = [
		join(cwd, "bin", "catseye-ocaml"),
		join(cwd, "bin", "catseye"),
		join(cwd, "vendor", "catseye", "bin", "catseye-ocaml"),
	];
	for (const p of localCandidates) {
		if (existsSync(p)) return resolve(p);
	}

	// Check relative to extension install (pi extensions may be in a catseye project)
	const extDirCandidates = [
		join(__dirname, "..", "..", "bin", "catseye-ocaml"),
		join(__dirname, "..", "..", "..", "catseye", "bin", "catseye-ocaml"),
	];
	for (const p of extDirCandidates) {
		if (existsSync(p)) return resolve(p);
	}

	// Fall back to global install locations
	const globalCandidates = [
		join(process.env.HOME || "/root", ".local/bin/catseye"),
		join(process.env.HOME || "/root", ".local/bin/catseye-ocaml"),
		"/usr/local/bin/catseye",
		"/usr/local/bin/catseye-ocaml",
	];
	for (const p of globalCandidates) {
		if (existsSync(p)) return p;
	}

	// Last resort: check PATH
	const result = spawnSync("which", ["catseye"], {
		encoding: "utf-8",
		timeout: 5_000,
	});
	const which = result.stdout?.trim();
	if (which) return which;

	return null;
}

function findRules(cwd: string): string | null {
	// Prefer local rules in the project (matching local binary preference)
	const candidates = [
		join(cwd, "src", "ocaml", "rules"),
		join(cwd, "vendor", "catseye", "src/ocaml/rules"),
		// Check relative to extension install
		join(__dirname, "..", "..", "src", "ocaml", "rules"),
		join(__dirname, "..", "..", "..", "catseye", "src", "ocaml", "rules"),
		// Global install
		join(process.env.HOME || "/root", ".local/lib/catseye/rules"),
		"/usr/local/lib/catseye/rules",
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
			"Run Catseye static security scanner on the project. Detects SSRF, injection (SQL/command/path/LDAP), open redirects, hardcoded secrets, weak crypto, missing timeouts, ReDoS, and more via taint analysis on Crystal, Elixir, Gleam, JavaScript, TypeScript, Svelte, OCaml, and Rust code. Also detects code smells (complexity, god objects, deep nesting, long parameter lists) and AI antipatterns (hallucinated methods, hardcoded URLs). Returns structured findings with taint flow traces.",
		promptSnippet: "Scan for security vulnerabilities and code smells",
		promptGuidelines: [
			"Use catseye_scan when the user asks to scan for security issues, code quality, or antipatterns.",
			"After scanning, triage findings as Real/False Positive/Won't Fix before proposing fixes.",
			"The flat taint engine is used by default. Use cfg=true for branch-aware analysis (more findings).",
			"Common false positives: DeadCode on early-return guards, SSRF on hardcoded URLs, GodObject on cohesive domain classes.",
			"Sanitizer calls (File.expand_path, URI.parse, validate_*) automatically suppress downstream findings.",
		],
		parameters: Type.Object({
			directory: Type.Optional(
				Type.String({
					description: "Directory to scan (defaults to src/ or client/src/)",
				}),
			),
			rules_dir: Type.Optional(
				Type.String({
					description: "Path to KDL rules directory (auto-detected if omitted)",
				}),
			),
			cfg: Type.Optional(
				Type.Boolean({
					description:
						"Use IL/CFG-based taint engine — more sensitive, branch-aware analysis (default: false)",
					default: false,
				}),
			),
			ai_lint: Type.Optional(
				Type.Boolean({
					description: "Enable AI antipattern detection (default: true)",
					default: true,
				}),
			),
			claws: Type.Optional(
				Type.Boolean({
					description: "Enable code smell detection (default: true)",
					default: true,
				}),
			),
			claws_suppress: Type.Optional(
				Type.Array(
					Type.String({
						description:
							"Glob patterns for directories to suppress in Claws findings",
					}),
				),
				{
					description: "Claws suppression patterns",
				},
			),
		}),

		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const binary = findBinary(ctx.cwd);
			if (!binary) {
				return {
					content: [
						{
							type: "text",
							text: "Catseye binary not found. Install with: just install or add to PATH.",
						},
					],
					isError: true,
				};
			}

			const rules = params.rules_dir || findRules(ctx.cwd);
			if (!rules) {
				return {
					content: [
						{
							type: "text",
							text: "Catseye KDL rules not found. Set --rules_dir or install to ~/.local/lib/catseye/rules/",
						},
					],
					isError: true,
				};
			}

			const target = params.directory || findSourceDir(ctx.cwd) || ctx.cwd;

			const args: string[] = ["--rules", rules, "--format", "json"];
			if (params.cfg) args.push("--cfg");
			if (params.ai_lint !== false) args.push("--ai-lint");
			if (params.claws !== false) args.push("--claws");
			args.push("--elixir");
			args.push(target);

			// Use spawnSync (no shell) to avoid shell overhead and SIGPIPE issues.
			// Catseye exits with code 1 when findings exist — that's not an error.
			//
			// The OCaml binary finds the Crystal extractor at bin/catseye-crystal-extractor
			// relative to CWD. The binary lives in <project>/bin/, so the project root
			// is two levels up. We set cwd to the project root so the extractor is found.
			// Target and rules are absolute paths so they work from any cwd.
			const binaryDir = resolve(binary, "..");
			const projectRoot = resolve(binaryDir, "..");
			const extractorPath = join(
				projectRoot,
				"bin",
				"catseye-crystal-extractor",
			);
			const env = { ...process.env } as Record<string, string>;
			// Also set env var for the direct-parse code path in crystal_mapper.ml
			if (existsSync(extractorPath)) {
				env.CATSEYE_CRYSTAL_EXTRACTOR = extractorPath;
			}

			// Set cwd to the catseye project root if the extractor is there,
			// otherwise fall back to ctx.cwd
			const scanCwd = existsSync(extractorPath) ? projectRoot : ctx.cwd;

			const proc = spawnSync(binary, args, {
				encoding: "utf-8",
				maxBuffer: 50 * 1024 * 1024,
				timeout: 120_000,
				cwd: scanCwd,
				env,
				stdio: ["ignore", "pipe", "pipe"],
			});

			if (proc.error) {
				return {
					content: [
						{
							type: "text",
							text: `Scan failed: ${proc.error.message}`,
						},
					],
					isError: true,
				};
			}

			// Accept exit codes 0 (clean) and 1 (findings found) as success.
			// Code >1 is a real error.
			const stdout = proc.stdout || "";
			const stderr = proc.stderr || "";
			if (proc.status != null && proc.status > 1) {
				return {
					content: [
						{
							type: "text",
							text: `Scan failed (exit ${proc.status}). stderr: ${stderr.slice(0, 1000)}`,
						},
					],
					isError: true,
				};
			}

			if (proc.signal) {
				return {
					content: [
						{
							type: "text",
							text: `Scan killed by signal ${proc.signal}.`,
						},
					],
					isError: true,
				};
			}

			// Empty output is likely a stale/broken binary — give a helpful message
			if (!stdout.trim()) {
				return {
					content: [
						{
							type: "text",
							text: `Scan produced no output. Binary: ${binary} | Rules: ${rules}\nThis usually means a stale global install. Run: just install`,
						},
					],
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
					if (depth === 0) {
						end = i + 1;
						break;
					}
				}
				result = JSON.parse(stdout.slice(start, end));
			} catch {
				return {
					content: [
						{
							type: "text",
							text: `Failed to parse scan output. Raw output:\n${stdout.slice(0, 2000)}`,
						},
					],
					isError: true,
				};
			}

			const findings = result.findings || [];
			const errors = findings.filter(
				(f) => f.severity === "High" || f.severity === "Critical",
			).length;
			const warnings = findings.filter(
				(f) => f.severity === "Medium" || f.severity === "Low",
			).length;

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
					const icon =
						f.severity === "High" || f.severity === "Critical" ? "🔴" : "⚠️";
					const file = f.file.replace(ctx.cwd + "/", "");
					const flow =
						f.flow && f.flow.length > 0
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
