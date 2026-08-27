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
MAX_PARAMETH_TARGETS = 60
_STATIC_SUFFIXES = {
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mjs",
    ".pdf", ".png", ".svg", ".webp", ".woff", ".woff2",
}


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _service_display(item: dict[str, Any]) -> str:
    name = str(item.get("service_name") or item.get("service") or "").strip()
    product = str(item.get("product") or "").strip()
    version = str(item.get("version") or "").strip()
    extra = str(item.get("extra_info") or "").strip()
    product_text = " ".join(value for value in (product, version) if value)
    if extra:
        product_text = f"{product_text} ({extra})" if product_text else extra
    if name and product_text:
        return f"{name} — {product_text}"
    return name or product_text


def _technology_list(record: dict[str, Any]) -> list[str]:
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


def _parameth_parameter_names(lines: list[str]) -> list[str]:
    """Parameth 버전별 출력 차이를 허용하며 명시적으로 표시된 파라미터만 정규화한다."""
    names: list[str] = []
    patterns = (
        re.compile(r"parameters?\s+(?:found\s*)?[:=]\s*([A-Za-z0-9_.-]+)", re.IGNORECASE),
        re.compile(r"\[\+\]\s*([A-Za-z_$][A-Za-z0-9_$.-]*)\s*(?:=>|$)"),
    )
    for line in lines:
        for pattern in patterns:
            match = pattern.search(line)
            if match and match.group(1) not in names:
                names.append(match.group(1))
                break
    return names


def _parameth_candidate(value: str, policy: ScopePolicy) -> str | None:
    try:
        policy.validate_url(value)
    except PolicyError:
        return None
    parsed = urlsplit(value)
    if Path(parsed.path).suffix.lower() in _STATIC_SUFFIXES:
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _merge_web_fingerprints(
    services: list[dict[str, Any]], records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Nmap 서비스 결과에 HTTPX 웹 서버/기술 정보를 같은 host:port 기준으로 합친다."""
    merged = [dict(item) for item in services]
    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for item in merged:
        try:
            key = (str(item.get("host") or ""), int(item.get("port") or 0))
        except (TypeError, ValueError):
            continue
        by_key[key] = item

    for record in records:
        url = str(record.get("url") or "")
        parsed = urlsplit(url)
        if not parsed.hostname:
            continue
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        item = by_key.get((parsed.hostname, port))
        if item is None:
            continue
        technologies = _technology_list(record)
        web_server = _web_server(record)
        item.update(
            {
                "web_url": url,
                "http_status": record.get("status_code"),
                "title": record.get("title"),
                "web_server": web_server,
                "technologies": technologies,
            }
        )
        if parsed.scheme == "https":
            item["tls"] = True
        display = _service_display(item)
        if web_server and web_server.lower() not in display.lower():
            display = f"{display}; server={web_server}" if display else f"server={web_server}"
        item["service"] = display

    return sorted(merged, key=lambda item: (str(item.get("host")), int(item.get("port") or 0)))


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
                "-sV",
                "--version-light",
                "--open",
                "-T4",
                "-p",
                ports,
                "-iL",
                remote,
                "-oX",
                "-",
            ],
            process_timeout=1200,
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
                        product = service_node.attrib.get("product", "") if service_node is not None else ""
                        version = service_node.attrib.get("version", "") if service_node is not None else ""
                        extra_info = service_node.attrib.get("extrainfo", "") if service_node is not None else ""
                        tunnel = service_node.attrib.get("tunnel", "") if service_node is not None else ""
                        method = service_node.attrib.get("method", "") if service_node is not None else ""
                        try:
                            confidence = int(service_node.attrib.get("conf", "0")) if service_node is not None else 0
                        except ValueError:
                            confidence = 0
                        cpes = []
                        if service_node is not None:
                            cpes = [
                                str(node.text).strip()
                                for node in service_node.findall("cpe")
                                if node.text and str(node.text).strip()
                            ]

                        hosts.add(address)
                        item: dict[str, Any] = {
                            "host": address,
                            "port": port,
                            "protocol": protocol,
                            "service_name": service_name,
                            "product": product,
                            "version": version,
                            "extra_info": extra_info,
                            "tunnel": tunnel,
                            "detection_method": method,
                            "confidence": confidence,
                            "cpes": cpes,
                            "evidence": "raw/network_discovery.xml",
                        }
                        item["service"] = _service_display(item)
                        services.append(item)

        run_dir = self.store.run_dir(state["run_id"])
        hosts_path = run_dir / "parsed" / "hosts.txt"
        hosts_path.write_text(
            "\n".join(sorted(hosts)) + ("\n" if hosts else ""),
            encoding="utf-8",
            newline="\n",
        )
        services_path = run_dir / "parsed" / "network-services.json"
        sorted_services = sorted(services, key=lambda item: (item["host"], item["port"]))
        atomic_write_json(services_path, sorted_services)
        inventory_path = run_dir / "parsed" / "service-inventory.json"
        atomic_write_json(inventory_path, sorted_services)
        self.store.add_artifact(state, hosts_path, "hosts", "network_discovery")
        self.store.add_artifact(state, services_path, "services", "network_discovery")
        self.store.add_artifact(state, inventory_path, "service-inventory", "network_discovery")
        return ToolOutcome(
            result.exit_code,
            f"Fingerprint {len(services)} scoped services across {len(hosts)} hosts",
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
                "-server",
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

        normalized_web = []
        for record in records:
            url = str(record.get("url") or "")
            parsed = urlsplit(url)
            normalized_web.append(
                {
                    "url": url,
                    "host": parsed.hostname,
                    "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                    "scheme": parsed.scheme,
                    "status_code": record.get("status_code"),
                    "title": record.get("title"),
                    "web_server": _web_server(record),
                    "technologies": _technology_list(record),
                }
            )
        web_fingerprints = run_dir / "parsed" / "web-fingerprints.json"
        atomic_write_json(web_fingerprints, normalized_web)

        service_list = services if isinstance(services, list) else []
        inventory = _merge_web_fingerprints(service_list, records)
        atomic_write_json(services_path, inventory)
        inventory_path = run_dir / "parsed" / "service-inventory.json"
        atomic_write_json(inventory_path, inventory)

        self.store.add_artifact(state, alive, "urls", "httpx")
        self.store.add_artifact(state, details, "parsed", "httpx")
        self.store.add_artifact(state, web_fingerprints, "web-fingerprints", "httpx")
        self.store.add_artifact(state, inventory_path, "service-inventory", "httpx")
        return ToolOutcome(
            result.exit_code,
            f"Confirmed {len(set(urls))} live web services and enriched service fingerprints",
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
        run_dir = self.store.run_dir(state["run_id"])
        candidates: list[str] = []

        def add(value: str) -> None:
            candidate = _parameth_candidate(value, policy)
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        # 소스에서 직접 확인한 요청을 우선하고, 크롤 URL과 origin을 뒤에 붙인다.
        try:
            source_endpoints = json.loads(
                (run_dir / "parsed" / "source-endpoints.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            source_endpoints = []
        for item in source_endpoints if isinstance(source_endpoints, list) else []:
            if isinstance(item, dict) and item.get("endpoint"):
                add(str(item["endpoint"]))

        katana_path = run_dir / "parsed" / "katana-urls.txt"
        if katana_path.exists():
            for value in _unique_lines(katana_path.read_text(encoding="utf-8")):
                add(value)
        for value in self._live_urls(policy, state):
            add(_origin(value))

        targets = candidates[:MAX_PARAMETH_TARGETS]
        if not targets:
            return ToolOutcome(0, "Parameth skipped because no live scoped URL exists", skipped=True)

        wordlist = "/opt/recon-wordlists/params-small.txt"
        results: list[dict[str, Any]] = []
        errors: list[str] = []
        failed = False
        total = 0
        for index, target in enumerate(targets, start=1):
            policy.validate_url(target)
            result = self.backend.run(
                ["parameth", "-u", target, "-p", wordlist],
                process_timeout=900,
            )
            self._write_indexed_result(state, "parameth", index, result)
            failed = failed or result.exit_code != 0
            if result.stderr.strip():
                errors.append(f"{target}: {result.stderr.strip()}")
            interesting = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip().startswith("[") or "parameter" in line.lower()
            ]
            parameters = _parameth_parameter_names(interesting)
            total += len(parameters)
            results.append(
                {
                    "target": target,
                    "parameters": parameters,
                    "interesting_lines": interesting,
                    "evidence": f"raw/parameth-{index:03d}.log",
                }
            )

        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "parameth.json"
        atomic_write_json(parsed, results)
        self.store.add_artifact(state, parsed, "parsed", "parameth")
        return ToolOutcome(
            1 if failed else 0,
            f"Recorded {total} parameter candidates across {len(targets)} scoped endpoints",
            total,
            error="\n".join(errors),
        )
