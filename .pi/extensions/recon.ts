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

// Python을 설치 방식에 의존하지 않고 프로젝트의 code/에서 직접 불러온다.
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

export default function (pi: ExtensionAPI) {
  // Pi가 정책 검사를 우회해 리콘 명령을 직접 실행하지 못하게 한다.
  pi.on("tool_call", async (event) => {
    if (event.toolName !== "bash") return undefined;
    const input = event.input as { command?: unknown };
    const command = typeof input.command === "string" ? input.command : "";
    const directRecon = /(?:^|\s)(?:docker\s+(?:container\s+)?(?:exec|run)|subfinder|assetfinder|amass|httpx|waybackurls|katana|gobuster|parameth)(?:\s|$)|recon_harness\.cli\s+start/i;
    if (directRecon.test(command)) {
      return { block: true, reason: "리콘은 recon_start를 통해서만 실행합니다." };
    }
    return undefined;
  });

  pi.registerTool({
    name: "recon_start",
    label: "Recon: 시작",
    description: "Run complete recon for one allowed domain. Katana always runs. Gobuster and Parameth run only when dos_allowed is true.",
    parameters: Type.Object({
      domain: Type.String({ description: "The single allowed domain" }),
      dos_allowed: Type.Boolean({ description: "Whether the program explicitly allows high-volume Gobuster and Parameth requests" }),
    }),
    async execute(_toolCallId, params, signal) {
      const args = ["start", params.domain];
      if (params.dos_allowed) args.push("--dos-allowed");
      return toolResult(await runCli(args, signal));
    },
  });

  pi.registerTool({
    name: "recon_status",
    label: "Recon: 상태",
    description: "Read a stored run without sending network requests.",
    parameters: Type.Object({ run_id: Type.String() }),
    async execute(_toolCallId, params, signal) {
      return toolResult(await runCli(["status", "--run", params.run_id], signal));
    },
  });
}
