import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const extensionDir = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(extensionDir, "../..");

type CliResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
  parsed?: unknown;
};

function pythonInvocation(args: string[]) {
  return process.platform === "win32"
    ? { command: "py", args: ["-3", "-m", "recon_harness.cli", ...args] }
    : { command: "python3", args: ["-m", "recon_harness.cli", ...args] };
}

function runCli(args: string[], signal?: AbortSignal): Promise<CliResult> {
  const invocation = pythonInvocation(args);
  return new Promise((resolvePromise, reject) => {
    const child = spawn(invocation.command, invocation.args, {
      cwd: projectRoot,
      env: { ...process.env, PYTHONPATH: resolve(projectRoot, "code") },
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    const abort = () => child.kill("SIGTERM");
    signal?.addEventListener("abort", abort, { once: true });
    child.on("error", reject);
    child.on("close", (code) => {
      signal?.removeEventListener("abort", abort);
      let parsed: unknown;
      try { parsed = JSON.parse(stdout); } catch { parsed = undefined; }
      resolvePromise({ exitCode: code ?? 1, stdout, stderr, parsed });
    });
  });
}

function toolResult(result: CliResult) {
  return {
    content: [{
      type: "text" as const,
      text: result.exitCode === 0
        ? (result.stdout.trim() || "완료")
        : `실행 실패 (exit ${result.exitCode})\n${result.stderr.trim() || result.stdout.trim()}`,
    }],
    details: { exitCode: result.exitCode, data: result.parsed, stderr: result.stderr },
    isError: result.exitCode !== 0,
  };
}

const scopeParameters = {
  targets: Type.Array(Type.String(), { minItems: 1, description: "허용 IPv4 또는 CIDR" }),
  ports: Type.Optional(Type.Array(Type.Integer({ minimum: 1, maximum: 65535 }))),
  profile: Type.Optional(Type.Union([Type.Literal("fast"), Type.Literal("deep")])),
  budget_minutes: Type.Optional(Type.Integer({ minimum: 1, maximum: 120 })),
  tls_verify: Type.Optional(Type.Boolean()),
};

function scopeArgs(params: {
  targets: string[];
  ports?: number[];
  profile?: "fast" | "deep";
  budget_minutes?: number;
  tls_verify?: boolean;
}) {
  const args = [...params.targets];
  if (params.ports?.length) args.push("--ports", params.ports.join(","));
  if (params.profile) args.push("--profile", params.profile);
  if (params.budget_minutes) args.push("--budget-minutes", String(params.budget_minutes));
  if (params.tls_verify) args.push("--tls-verify");
  return args;
}

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "recon_create",
    label: "Recon V2: Run 생성",
    description: "Create a scoped competition web Recon V2 run without network requests.",
    parameters: Type.Object(scopeParameters),
    async execute(_toolCallId, params, signal) {
      return toolResult(await runCli(["create", ...scopeArgs(params)], signal));
    },
  });

  pi.registerTool({
    name: "recon_run",
    label: "Recon V2: 단계 실행",
    description: "Run one decision stage or tool in an existing V2 run.",
    parameters: Type.Object({
      run_id: Type.String(),
      target: Type.Union([
        Type.Literal("inventory"), Type.Literal("mapping"),
        Type.Literal("normalize"), Type.Literal("expansion"),
        Type.Literal("network_discovery"), Type.Literal("httpx"),
        Type.Literal("robots_txt"), Type.Literal("katana"),
        Type.Literal("source_comments"), Type.Literal("surface"),
        Type.Literal("gobuster_dir"), Type.Literal("nuclei"),
      ]),
    }),
    async execute(_toolCallId, params, signal) {
      const stages = new Set(["inventory", "mapping", "normalize", "expansion"]);
      const command = stages.has(params.target) ? "stage" : "tool";
      return toolResult(await runCli([command, "--run", params.run_id, params.target], signal));
    },
  });

  pi.registerTool({
    name: "recon_report",
    label: "Recon V2: 요약 갱신",
    description: "Rebuild normalized routes, top candidates and summary without network requests.",
    parameters: Type.Object({ run_id: Type.String() }),
    async execute(_toolCallId, params, signal) {
      return toolResult(await runCli(["report", "--run", params.run_id], signal));
    },
  });

  pi.registerTool({
    name: "recon_status",
    label: "Recon V2: 상태",
    description: "Read one V2 run without sending network requests.",
    parameters: Type.Object({ run_id: Type.String() }),
    async execute(_toolCallId, params, signal) {
      return toolResult(await runCli(["status", "--run", params.run_id], signal));
    },
  });
}
