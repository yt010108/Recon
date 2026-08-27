"""격리된 대회 내부망을 위한 웹 서비스 발견/열거 어댑터."""

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


COMPETITION_KATANA_DEPTH = 3


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


class CompetitionToolRunner(DeepDiscoveryToolRunner):
    """인터넷 OSINT 대신 명시된 IPv4/CIDR 안에서 웹 표면을 빠르게 만든다."""

    def _live_urls(self, policy: ScopePolicy, state: dict[str, Any]) -> list[str]:
        path = self.store.run_dir(state["run_id"]) / "parsed" / "alive-urls.txt"
        urls = _unique_lines(path.read_text(encoding="utf-8")) if path.exists() else []
        accepted: list[str] = []
        for value in urls:
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
        if policy.mode != "competition":
            raise PolicyError("network_discovery is only available in competition mode")

        remote = self._copy_lines_input(state, "nmap-targets.txt", policy.targets)
        ports = ",".join(str(port) for port in policy.allowed_ports)
        result = self.backend.run(
            [
                "nmap",
                "-n",
                "-Pn",
                "-sT",
                "--open",
                "-T4",
                "-p",
                ports,
                "-iL",
                remote,
                "-oX",
                "-",
            ],
            process_timeout=900,
        )
        self._write_result(state, "network_discovery", result, extension="xml")

        services: list[dict[str, Any]] = []
        hosts: set[str] = set()
        if result.stdout.strip():
            try:
                root = ET.fromstring(result.stdout)
            except ET.ParseError:
                root = None
            if root is not None:
                for host_node in root.findall("host"):
                    status = host_node.find("status")
                    if status is not None and status.attrib.get("state") != "up":
                        continue
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
                        protocol = port_node.attrib.get("protocol", "tcp")
                        service_node = port_node.find("service")
                        service_name = service_node.attrib.get("name", "") if service_node is not None else ""
                        hosts.add(address)
                        services.append(
                            {
                                "host": address,
                                "port": port,
                                "protocol": protocol,
                                "service": service_name,
                                "evidence": "raw/network_discovery.xml",
                            }
                        )

        run_dir = self.store.run_dir(state["run_id"])
        hosts_path = run_dir / "parsed" / "hosts.txt"
        hosts_path.write_text(
            "\n".join(sorted(hosts)) + ("\n" if hosts else ""),
            encoding="utf-8",
            newline="\n",
        )
        services_path = run_dir / "parsed" / "network-services.json"
        atomic_write_json(
            services_path,
            sorted(services, key=lambda item: (item["host"], item["port"])),
        )
        self.store.add_artifact(state, hosts_path, "hosts", "network_discovery")
        self.store.add_artifact(state, services_path, "services", "network_discovery")
        return ToolOutcome(
            result.exit_code,
            f"Found {len(hosts)} hosts with {len(services)} open scoped ports",
            len(services),
            error=result.stderr.strip(),
        )

    def run_httpx(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        run_dir = self.store.run_dir(state["run_id"])
        services_path = run_dir / "parsed" / "network-services.json"
        try:
            services = json.loads(services_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            services = []

        targets: list[str] = []
        for item in services if isinstance(services, list) else []:
            host = str(item.get("host") or "")
            try:
                port = int(item.get("port") or 0)
                policy.validate_host(host)
            except (TypeError, ValueError, PolicyError):
                continue
            if port not in policy.allowed_ports:
                continue
            target = f"{host}:{port}"
            if target not in targets:
                targets.append(target)
        if not targets:
            return ToolOutcome(0, "HTTPX skipped because no scoped open ports were found", skipped=True)

        remote = self._copy_lines_input(state, "httpx-input.txt", targets)
        result = self.backend.run(
            [
                "httpx",
                "-l",
                remote,
                "-silent",
                "-j",
                "-sc",
                "-title",
                "-td",
                "-duc",
            ],
            process_timeout=600,
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

        alive = run_dir / "parsed" / "alive-urls.txt"
        alive.write_text(
            "\n".join(sorted(set(urls))) + ("\n" if urls else ""),
            encoding="utf-8",
            newline="\n",
        )
        details = run_dir / "parsed" / "httpx.json"
        atomic_write_json(details, records)
        self.store.add_artifact(state, alive, "urls", "httpx")
        self.store.add_artifact(state, details, "parsed", "httpx")
        return ToolOutcome(
            result.exit_code,
            f"Confirmed {len(set(urls))} live in-scope web services",
            len(set(urls)),
            error=result.stderr.strip(),
        )

    def run_katana(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        urls = self._live_urls(policy, state)
        if not urls:
            return ToolOutcome(0, "Katana skipped because no live scoped URL exists", skipped=True)

        remote = self._copy_lines_input(state, "katana-input.txt", urls)
        origins = sorted({_origin(value) for value in urls})
        scope_regex = r"^(?:" + "|".join(re.escape(value) for value in origins) + r")(?:/|$)"
        args = [
            "katana",
            "-list",
            remote,
            "-silent",
            "-d",
            str(COMPETITION_KATANA_DEPTH),
            "-jc",
            "-cs",
            scope_regex,
        ]
        result = self.backend.run(args, process_timeout=900)
        self._write_result(state, "katana", result)

        discovered: list[str] = []
        for url in _unique_lines(result.stdout):
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            discovered.append(url)
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "katana-urls.txt"
        parsed.write_text(
            "\n".join(sorted(set(discovered))) + ("\n" if discovered else ""),
            encoding="utf-8",
            newline="\n",
        )
        self.store.add_artifact(state, parsed, "urls", "katana")
        return ToolOutcome(
            result.exit_code,
            f"Crawled {len(set(discovered))} in-scope URLs at depth {COMPETITION_KATANA_DEPTH}",
            len(set(discovered)),
            error=result.stderr.strip(),
        )

    def run_gobuster_dir(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        origins = sorted({_origin(value) for value in self._live_urls(policy, state)})
        if not origins:
            return ToolOutcome(0, "Gobuster skipped because no live scoped URL exists", skipped=True)

        wordlist = "/opt/recon-wordlists/web-common.txt"
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        failed = False
        pattern = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
        wildcard_pattern = re.compile(
            r"non existing urls?.*?\(Length:\s*(\d+)\)",
            flags=re.IGNORECASE | re.DOTALL,
        )

        for index, origin in enumerate(origins, start=1):
            policy.validate_url(origin)
            args = ["gobuster", "dir", "-u", origin, "-w", wordlist, "-q"]
            result = self.backend.run(args, process_timeout=900)
            wildcard_match = wildcard_pattern.search(result.stderr)
            if result.exit_code != 0 and wildcard_match:
                result = self.backend.run(
                    [*args, "--exclude-length", wildcard_match.group(1)],
                    process_timeout=900,
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

        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "gobuster-dir.json"
        atomic_write_json(parsed, findings)
        self.store.add_artifact(state, parsed, "parsed", "gobuster_dir")
        return ToolOutcome(
            1 if failed else 0,
            f"Found {len(findings)} content paths across {len(origins)} web services",
            len(findings),
            error="\n".join(errors),
        )

    def run_parameth(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        origins = sorted({_origin(value) for value in self._live_urls(policy, state)})
        if not origins:
            return ToolOutcome(0, "Parameth skipped because no live scoped URL exists", skipped=True)

        wordlist = "/opt/recon-wordlists/params-small.txt"
        results: list[dict[str, Any]] = []
        errors: list[str] = []
        failed = False
        total = 0
        for index, origin in enumerate(origins, start=1):
            policy.validate_url(origin)
            result = self.backend.run(
                ["parameth", "-u", origin, "-p", wordlist],
                process_timeout=900,
            )
            self._write_indexed_result(state, "parameth", index, result)
            failed = failed or result.exit_code != 0
            if result.stderr.strip():
                errors.append(f"{origin}: {result.stderr.strip()}")
            interesting = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip().startswith("[") or "parameter" in line.lower()
            ]
            total += len(interesting)
            results.append(
                {
                    "target": origin,
                    "interesting_lines": interesting,
                    "evidence": f"raw/parameth-{index:03d}.log",
                }
            )

        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "parameth.json"
        atomic_write_json(parsed, results)
        self.store.add_artifact(state, parsed, "parsed", "parameth")
        return ToolOutcome(
            1 if failed else 0,
            f"Recorded {total} parameter result lines across {len(origins)} web services",
            total,
            error="\n".join(errors),
        )
