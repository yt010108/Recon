"""허용된 대회 IPv4 범위에서 웹 표면을 수집하는 도구 어댑터."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from .deep_discovery import DeepDiscoveryToolRunner
from .policy import PolicyError, ScopePolicy
from .storage import atomic_write_json
from .tools import ToolOutcome, _unique_lines


STATIC_SUFFIXES = {
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".map", ".pdf", ".png",
    ".svg", ".webp", ".woff", ".woff2",
}
INTERESTING_COMMENT = re.compile(
    r"\b(?:todo|fixme|admin|internal|debug|secret|password|token|api|upload|redirect|callback)\b",
    re.IGNORECASE,
)


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _technologies(record: dict[str, Any]) -> list[str]:
    value = record.get("tech") or record.get("technologies") or []
    if isinstance(value, str):
        values = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, list):
        values = [str(item).strip() for item in value if str(item).strip()]
    else:
        values = []
    return list(dict.fromkeys(values))


def _web_server(record: dict[str, Any]) -> str:
    for key in ("webserver", "web_server", "server"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


class CompetitionToolRunner(DeepDiscoveryToolRunner):
    """도구 출력은 증거로 저장하고 최종 정규화는 surface 단계에 맡긴다."""

    @staticmethod
    def _timeout(policy: ScopePolicy, fast: int, deep: int) -> int:
        requested = fast if policy.profile == "fast" else deep
        return max(30, min(requested, policy.budget_minutes * 60))

    def _live_urls(self, policy: ScopePolicy, state: dict[str, Any]) -> list[str]:
        path = self.store.run_dir(state["run_id"]) / "parsed" / "alive-urls.txt"
        accepted: list[str] = []
        for value in _unique_lines(path.read_text(encoding="utf-8")) if path.exists() else []:
            try:
                policy.validate_url(value)
            except PolicyError:
                continue
            if value not in accepted:
                accepted.append(value)
        return accepted

    def _write_indexed_result(self, state: dict[str, Any], tool: str, index: int, result) -> None:
        run_dir = self.store.run_dir(state["run_id"])
        stdout_path = run_dir / "raw" / f"{tool}-{index:03d}.log"
        stderr_path = run_dir / "raw" / f"{tool}-{index:03d}.stderr.log"
        stdout_path.write_text(result.stdout, encoding="utf-8", newline="\n")
        stderr_path.write_text(result.stderr, encoding="utf-8", newline="\n")
        self.store.add_artifact(state, stdout_path, "raw", tool)
        if result.stderr:
            self.store.add_artifact(state, stderr_path, "stderr", tool)

    def run_network_discovery(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        remote = self._copy_lines_input(state, "nmap-targets.txt", policy.targets)
        ports = ",".join(str(port) for port in policy.allowed_ports)
        result = self.backend.run(
            [
                "nmap", "-n", "-Pn", "-sT", "-sV", "--version-light", "--open",
                "-T4", "-p", ports, "-iL", remote, "-oX", "-",
            ],
            process_timeout=self._timeout(policy, 60, 300),
        )
        self._write_result(state, "network_discovery", result, extension="xml")

        services: list[dict[str, Any]] = []
        if result.stdout.strip():
            try:
                root = ET.fromstring(result.stdout)
            except ET.ParseError:
                root = None
            if root is not None:
                for host_node in root.findall("host"):
                    address = next(
                        (
                            node.attrib.get("addr", "")
                            for node in host_node.findall("address")
                            if node.attrib.get("addrtype") == "ipv4"
                        ),
                        "",
                    )
                    try:
                        policy.validate_host(address)
                    except PolicyError:
                        continue
                    for port_node in host_node.findall("./ports/port"):
                        state_node = port_node.find("state")
                        if state_node is None or state_node.attrib.get("state") != "open":
                            continue
                        try:
                            port = int(port_node.attrib.get("portid", "0"))
                        except ValueError:
                            continue
                        if port not in policy.allowed_ports:
                            continue
                        service_node = port_node.find("service")
                        item = {
                            "host": address,
                            "port": port,
                            "protocol": port_node.attrib.get("protocol", "tcp"),
                            "service_name": service_node.attrib.get("name", "") if service_node is not None else "",
                            "product": service_node.attrib.get("product", "") if service_node is not None else "",
                            "version": service_node.attrib.get("version", "") if service_node is not None else "",
                            "extra_info": service_node.attrib.get("extrainfo", "") if service_node is not None else "",
                            "evidence": "raw/network_discovery.xml",
                        }
                        services.append(item)

        services.sort(key=lambda item: (item["host"], item["port"]))
        run_dir = self.store.run_dir(state["run_id"])
        destination = run_dir / "parsed" / "network-services.json"
        atomic_write_json(destination, services)
        self.store.add_artifact(state, destination, "services", "network_discovery")
        return ToolOutcome(
            result.exit_code,
            f"Found {len(services)} allowed open services",
            len(services),
            error=result.stderr.strip(),
        )

    def run_httpx(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        run_dir = self.store.run_dir(state["run_id"])
        services = _json(run_dir / "parsed" / "network-services.json", [])
        targets: list[str] = []
        for item in services if isinstance(services, list) else []:
            try:
                host = policy.validate_host(str(item.get("host") or ""))
                port = int(item.get("port") or 0)
            except (PolicyError, TypeError, ValueError):
                continue
            if port in policy.allowed_ports:
                target = f"{host}:{port}"
                if target not in targets:
                    targets.append(target)
        if not targets:
            return ToolOutcome(0, "No open port was available for HTTP probing", skipped=True)

        remote = self._copy_lines_input(state, "httpx-input.txt", targets)
        result = self.backend.run(
            [
                "httpx", "-l", remote, "-silent", "-j", "-sc", "-title", "-td",
                "-server", "-ct", "-cl", "-duc",
            ],
            process_timeout=self._timeout(policy, 60, 180),
        )
        self._write_result(state, "httpx", result, extension="jsonl")

        records: list[dict[str, Any]] = []
        urls: list[str] = []
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            url = str(record.get("url") or "")
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            records.append(record)
            urls.append(url)

        alive_path = run_dir / "parsed" / "alive-urls.txt"
        alive_path.write_text(
            "\n".join(sorted(set(urls))) + ("\n" if urls else ""),
            encoding="utf-8",
            newline="\n",
        )
        details_path = run_dir / "parsed" / "httpx.json"
        atomic_write_json(details_path, records)
        origins = []
        for record in records:
            url = str(record.get("url") or "")
            parsed = urlsplit(url)
            origins.append(
                {
                    "url": _origin(url),
                    "host": parsed.hostname,
                    "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                    "scheme": parsed.scheme,
                    "status_code": record.get("status_code"),
                    "title": record.get("title"),
                    "content_type": record.get("content_type"),
                    "content_length": record.get("content_length"),
                    "web_server": _web_server(record),
                    "technologies": _technologies(record),
                    "evidence": "raw/httpx.jsonl",
                }
            )
        origins_path = run_dir / "normalized" / "origins.json"
        atomic_write_json(origins_path, origins)
        for path, kind in (
            (alive_path, "urls"),
            (details_path, "parsed"),
            (origins_path, "origins"),
        ):
            self.store.add_artifact(state, path, kind, "httpx")
        return ToolOutcome(
            result.exit_code,
            f"Confirmed {len(set(urls))} live web origins",
            len(set(urls)),
            error=result.stderr.strip(),
        )

    def run_katana(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        urls = self._live_urls(policy, state)
        if not urls:
            return ToolOutcome(0, "Katana skipped because no live origin exists", skipped=True)
        remote = self._copy_lines_input(state, "katana-input.txt", urls)
        origins = sorted({_origin(value) for value in urls})
        scope_regex = r"^(?:" + "|".join(re.escape(value) for value in origins) + r")(?:/|$)"
        depth = 1 if policy.profile == "fast" else 3
        result = self.backend.run(
            [
                "katana", "-list", remote, "-silent", "-d", str(depth), "-jc",
                "-c", "2", "-rl", "10", "-cs", scope_regex,
            ],
            process_timeout=self._timeout(policy, 60, 300),
        )
        self._write_result(state, "katana", result)
        discovered: list[str] = []
        for url in _unique_lines(result.stdout):
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            discovered.append(url)
        path = self.store.run_dir(state["run_id"]) / "parsed" / "katana-urls.txt"
        path.write_text(
            "\n".join(sorted(set(discovered))) + ("\n" if discovered else ""),
            encoding="utf-8",
            newline="\n",
        )
        self.store.add_artifact(state, path, "urls", "katana")
        return ToolOutcome(
            result.exit_code,
            f"Mapped {len(set(discovered))} scoped URLs at depth {depth}",
            len(set(discovered)),
            error=result.stderr.strip(),
        )

    def run_source_comments(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        outcome = super().run_source_comments(policy, state)
        run_dir = self.store.run_dir(state["run_id"])
        comments_path = run_dir / "parsed" / "source-comments.json"
        comments = _json(comments_path, [])
        interesting = [
            item
            for item in comments if isinstance(item, dict)
            and INTERESTING_COMMENT.search(str(item.get("text") or ""))
        ][:200]
        atomic_write_json(comments_path, interesting)
        endpoints = _json(run_dir / "parsed" / "source-endpoints.json", [])
        return ToolOutcome(
            outcome.exit_code,
            f"Recorded {len(endpoints)} source endpoint observations and {len(interesting)} relevant comments",
            len(endpoints) + len(interesting),
            error=outcome.error,
        )

    def run_gobuster_dir(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        origins = sorted({_origin(value) for value in self._live_urls(policy, state)})
        if not origins:
            return ToolOutcome(0, "Gobuster skipped because no live origin exists", skipped=True)
        budget_seconds = policy.budget_minutes * 60
        maximum_origins = max(1, budget_seconds // 30)
        omitted_origins = max(0, len(origins) - maximum_origins)
        origins = origins[:maximum_origins]
        per_origin_timeout = max(15, budget_seconds // len(origins))
        per_attempt_timeout = max(15, per_origin_timeout // 2)
        pattern = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
        wildcard = re.compile(r"non existing urls?.*?\(Length:\s*(\d+)\)", re.I | re.S)
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        failed = False
        for index, origin in enumerate(origins, start=1):
            args = [
                "gobuster", "dir", "-u", origin,
                "-w", "/opt/recon-wordlists/web-common.txt", "-q",
            ]
            if urlsplit(origin).scheme == "https" and not policy.tls_verify:
                args.append("-k")
            result = self.backend.run(
                args,
                process_timeout=min(300, per_attempt_timeout),
            )
            wildcard_match = wildcard.search(result.stderr)
            if result.exit_code != 0 and wildcard_match:
                result = self.backend.run(
                    [*args, "--exclude-length", wildcard_match.group(1)],
                    process_timeout=min(300, per_attempt_timeout),
                )
            self._write_indexed_result(state, "gobuster_dir", index, result)
            failed = failed or result.exit_code != 0
            if result.stderr.strip():
                errors.append(f"{origin}: {result.stderr.strip()}")
            for line in result.stdout.splitlines():
                match = pattern.search(line.strip())
                if not match:
                    continue
                url = urljoin(origin.rstrip("/") + "/", match.group(1).lstrip("/"))
                try:
                    policy.validate_url(url)
                except PolicyError:
                    continue
                findings.append(
                    {
                        "base_url": origin,
                        "url": url,
                        "path": match.group(1),
                        "status": int(match.group(2)),
                        "size": int(match.group(3)) if match.group(3) else None,
                        "evidence": f"raw/gobuster_dir-{index:03d}.log",
                    }
                )
        path = self.store.run_dir(state["run_id"]) / "parsed" / "gobuster-dir.json"
        atomic_write_json(path, findings)
        self.store.add_artifact(state, path, "parsed", "gobuster_dir")
        return ToolOutcome(
            1 if failed else 0,
            f"Found {len(findings)} paths across {len(origins)} origins"
            + (f"; omitted {omitted_origins} origins due to budget" if omitted_origins else ""),
            len(findings),
            error="\n".join(errors),
        )
