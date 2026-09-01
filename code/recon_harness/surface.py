"""수집량은 유지하고 URL을 기능 단위 route와 검토 후보로 정리한다."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .policy import PolicyError, ScopePolicy
from .storage import RunStore, atomic_write_json, atomic_write_text
from .tools import ToolOutcome


STATIC_SUFFIXES = {
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mjs",
    ".mp3", ".mp4", ".png", ".svg", ".webp", ".woff", ".woff2",
}
ROLE_WORDS = {
    "auth": {"login", "signin", "signup", "register", "auth", "oauth", "password", "reset"},
    "admin": {"admin", "manage", "dashboard", "console", "panel"},
    "api": {"api", "graphql", "swagger", "openapi", "rpc"},
    "file": {"upload", "download", "export", "import", "attachment", "file"},
    "operation": {"debug", "internal", "health", "metrics", "actuator"},
}
SINK_WORDS = {
    "file": {"upload", "import", "file", "path", "filename"},
    "url": {"url", "uri", "redirect", "return", "next", "callback", "webhook"},
    "object": {"id", "user", "account", "order", "document", "item", "seq"},
    "command": {"cmd", "command", "exec", "template", "render"},
}
UUID_RE = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I)


def _json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _lines(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []


def _normalized_path(path: str) -> str:
    parts = []
    for part in (path or "/").split("/"):
        if part.isdigit():
            part = "{int}"
        elif UUID_RE.fullmatch(part) or (len(part) >= 20 and re.fullmatch(r"[A-Za-z0-9_-]+", part)):
            part = "{token}"
        parts.append(part)
    result = "/".join(parts)
    return result if result.startswith("/") else "/" + result


def _labels(values: list[str], mapping: dict[str, set[str]]) -> list[str]:
    tokens = {
        token.lower()
        for value in values
        for token in re.split(r"[^A-Za-z0-9]+", value)
        if token
    }
    return [label for label, words in mapping.items() if tokens & words]


def build_surface(policy: ScopePolicy, state: dict[str, Any], store: RunStore) -> dict[str, Any]:
    run_dir = store.run_dir(state["run_id"])
    parsed = run_dir / "parsed"
    normalized = run_dir / "normalized"
    normalized.mkdir(exist_ok=True)
    observations: list[tuple[str, str, dict[str, Any]]] = []

    for name, tool in (
        ("wayback-urls.txt", "waybackurls"),
        ("alive-urls.txt", "httpx"),
        ("katana-urls.txt", "katana"),
    ):
        observations.extend((url, "GET", {"tool": tool, "artifact": f"parsed/{name}"}) for url in _lines(parsed / name))
    for line in _lines(parsed / "url-queue.jsonl"):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("url"):
            observations.append((str(item["url"]), "GET", {"tool": "url_discovery", "artifact": "parsed/url-queue.jsonl"}))
    for item in _json(parsed / "gobuster-dir.json", []):
        if isinstance(item, dict) and item.get("path"):
            observations.append((urljoin(policy.base_url.rstrip("/") + "/", str(item["path"]).lstrip("/")), "GET", {"tool": "gobuster_dir", "artifact": "parsed/gobuster-dir.json"}))
    for item in _json(parsed / "source-endpoints.json", []):
        if isinstance(item, dict) and item.get("endpoint"):
            observations.append((str(item["endpoint"]), str(item.get("method") or "GET").upper(), {"tool": "source_comments", "artifact": "parsed/source-endpoints.json", "source": item.get("source"), "line": item.get("line")}))

    routes: dict[str, dict[str, Any]] = {}
    for url, method, evidence in observations:
        try:
            policy.validate_url(url)
        except PolicyError:
            continue
        value = urlsplit(url)
        if Path(value.path).suffix.lower() in STATIC_SUFFIXES:
            continue
        port = value.port
        default = 443 if value.scheme == "https" else 80
        host = f"[{value.hostname}]" if value.hostname and ":" in value.hostname else str(value.hostname)
        netloc = host if port in {None, default} else f"{host}:{port}"
        origin = urlunsplit((value.scheme, netloc, "", "", ""))
        path = _normalized_path(value.path)
        params = sorted({name for name, _ in parse_qsl(value.query, keep_blank_values=True)})
        signature = "|".join((origin, method, path, ",".join(params)))
        route = routes.setdefault(signature, {"route_id": "route-" + hashlib.sha256(signature.encode()).hexdigest()[:12], "origin": origin, "method": method, "path": path, "query_parameters": params, "evidence": []})
        if evidence not in route["evidence"]:
            route["evidence"].append(evidence)

    previous = {
        item.get("route_id"): item
        for item in _json(normalized / "candidates.json", [])
        if isinstance(item, dict) and item.get("route_id")
    }
    candidates = []
    for route in routes.values():
        values = [route["path"], *route["query_parameters"]]
        roles = _labels(values, ROLE_WORDS)
        sinks = _labels(values, SINK_WORDS)
        score = (3 if route["method"] in {"POST", "PUT", "PATCH", "DELETE"} else 0) + (2 if route["query_parameters"] else 0) + (2 if roles else 0) + (2 if sinks else 0) + (1 if len({item["tool"] for item in route["evidence"]}) > 1 else 0)
        route.update({"roles": roles, "sink_hints": sinks, "priority_score": score})
        if score >= 2:
            old = previous.get(route["route_id"], {})
            candidates.append({**route, "priority": "P1" if score >= 6 else "P2" if score >= 4 else "P3", "route": route["origin"] + route["path"], "status": old.get("status", "unverified"), "notes": old.get("notes", ""), "next_action": "요청 method, 입력값과 접근 통제를 수동 확인한다."})
    ordered = sorted(routes.values(), key=lambda item: (item["origin"], item["path"], item["method"]))
    candidates = sorted(candidates, key=lambda item: (-item["priority_score"], item["route"]))[:20]
    coverage = {"observations": len(observations), "routes": len(ordered), "candidates": len(candidates), "stages": {name: item.get("status") for name, item in state["stages"].items()}}
    atomic_write_text(normalized / "routes.jsonl", "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in ordered))
    atomic_write_json(normalized / "candidates.json", candidates)
    atomic_write_json(normalized / "coverage.json", coverage)
    for name, kind in (("routes.jsonl", "routes"), ("candidates.json", "candidates"), ("coverage.json", "coverage")):
        store.add_artifact(state, normalized / name, kind, "surface")
    store.save(state)
    return {"routes": ordered, "candidates": candidates, "coverage": coverage}


def run_local_surface(policy: ScopePolicy, state: dict[str, Any], store: RunStore) -> ToolOutcome:
    result = build_surface(policy, state, store)
    return ToolOutcome(0, f"Normalized {len(result['routes'])} routes and selected {len(result['candidates'])} candidates", len(result["routes"]))
