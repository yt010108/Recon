"""Bounded URL discovery using existing recon artifacts."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from .policy import PolicyError, ScopePolicy
from .storage import RunStore, atomic_write_text
from .tools import ToolOutcome, _httpx_records, _katana_scope_regexes, _unique_lines


MAX_ROUNDS = 2
MAX_URLS = 1000
MAX_URLS_PER_ORIGIN = 100
MAX_KATANA_SEEDS_PER_ORIGIN = 3


def _lines(path: Path) -> list[str]:
    try:
        return _unique_lines(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []


def _json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _canonical_url(policy: ScopePolicy, value: str) -> str | None:
    try:
        policy.validate_url(value)
        parsed = urlsplit(value)
        port = parsed.port
    except (PolicyError, ValueError):
        return None
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    host = str(parsed.hostname).lower()
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _source_candidates(run_dir: Path) -> Iterator[tuple[str, str]]:
    for item in _json(run_dir / "parsed" / "source-endpoints.json", []):
        if isinstance(item, dict) and item.get("endpoint"):
            yield "source", str(item["endpoint"])

    for document in _json(run_dir / "parsed" / "robots.json", []):
        if not isinstance(document, dict):
            continue
        robots_url = str(document.get("url") or "")
        for directive in document.get("directives", []):
            if not isinstance(directive, dict):
                continue
            name = str(directive.get("name") or "").lower()
            value = str(directive.get("value") or "").strip()
            if name == "sitemap" and value:
                yield "robots", value
            elif name in {"allow", "disallow"} and value.startswith("/") and not any(
                marker in value for marker in ("*", "$")
            ):
                yield "robots", urljoin(robots_url, value)

    for source, name in (("katana", "katana-urls.txt"), ("wayback", "wayback-urls.txt")):
        for value in _lines(run_dir / "parsed" / name):
            yield source, value


class DiscoveryRunner:
    def __init__(self, adapter: Any, store: RunStore) -> None:
        self.adapter = adapter
        self.store = store

    def _load_queue(self, run_dir: Path) -> dict[str, dict[str, Any]]:
        frontier: dict[str, dict[str, Any]] = {}
        for line in _lines(run_dir / "parsed" / "url-queue.jsonl"):
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                continue
            status = str(item.get("status") or "queued")
            url = str(item["url"])
            frontier[url] = {
                "url": url,
                "sources": set(item.get("sources") or []),
                "round": int(item.get("round") or 0),
                "probed": status in {"probed", "live", "crawled"},
                "live": status in {"live", "crawled"},
                "status_code": item.get("status_code"),
                "content_type": item.get("content_type"),
            }
        return frontier

    def _add(
        self,
        policy: ScopePolicy,
        frontier: dict[str, dict[str, Any]],
        source: str,
        raw_url: str,
        round_number: int,
    ) -> bool:
        url = _canonical_url(policy, raw_url)
        if url is None:
            return False
        if url in frontier:
            frontier[url]["sources"].add(source)
            return False
        if len(frontier) >= MAX_URLS:
            return False
        origin = _origin(url)
        if sum(_origin(item) == origin for item in frontier) >= MAX_URLS_PER_ORIGIN:
            return False
        frontier[url] = {
            "url": url,
            "sources": {source},
            "round": round_number,
            "probed": False,
            "live": False,
            "status_code": None,
            "content_type": None,
        }
        return True

    def _baseline(
        self, policy: ScopePolicy, run_dir: Path
    ) -> tuple[set[str], set[str], set[str]]:
        probed: set[str] = set()
        live: set[str] = set()
        for item in _json(run_dir / "parsed" / "httpx.json", []):
            if isinstance(item, dict):
                for key in ("input", "url", "final_url"):
                    value = item.get(key)
                    if isinstance(value, str) and (url := _canonical_url(policy, value)):
                        probed.add(url)
        for value in _lines(run_dir / "parsed" / "alive-urls.txt"):
            if url := _canonical_url(policy, value):
                probed.add(url)
                live.add(url)
        for name in ("robots_txt.jsonl", "source_comments.jsonl", "source_assets.jsonl"):
            path = run_dir / "raw" / name
            if not path.exists():
                continue
            for item in _httpx_records(path.read_text(encoding="utf-8")):
                for key in ("input", "url", "final_url"):
                    value = item.get(key)
                    if isinstance(value, str) and (url := _canonical_url(policy, value)):
                        probed.add(url)
        crawled = {
            url
            for value in _lines(run_dir / "raw" / "katana-input.txt")
            if (url := _canonical_url(policy, value))
        }
        return probed, live, crawled

    @staticmethod
    def _record_urls(policy: ScopePolicy, record: dict[str, Any]) -> list[str]:
        urls: list[str] = []
        for key in ("input", "url", "final_url"):
            value = record.get(key)
            if isinstance(value, str) and (url := _canonical_url(policy, value)) and url not in urls:
                urls.append(url)
        return urls

    @staticmethod
    def _mark_probed(entry: dict[str, Any], record: dict[str, Any] | None) -> None:
        try:
            status = int((record or {}).get("status_code") or 0)
        except (TypeError, ValueError):
            status = 0
        entry["probed"] = True
        entry["live"] = bool(record) and status > 0 and not (record or {}).get("error")
        entry["status_code"] = status or None
        entry["content_type"] = (record or {}).get("content_type")

    def _probe(
        self, state: dict[str, Any], targets: list[str], round_number: int
    ) -> tuple[Any, list[dict[str, Any]]]:
        name = f"discovery-httpx-r{round_number}"
        remote = self.adapter._copy_lines_input(state, f"{name}-input.txt", targets)
        result = self.adapter.backend.run(
            ["httpx", "-l", remote, "-silent", "-j", "-sc", "-ct", "-cl", "-duc"],
            process_timeout=900,
        )
        self.adapter._write_result(state, name, result, extension="jsonl")
        return result, _httpx_records(result.stdout)

    def _seeds(
        self, frontier: dict[str, dict[str, Any]], crawled: set[str]
    ) -> list[str]:
        seeds: list[str] = []
        per_origin = Counter(_origin(url) for url in crawled)
        seen_origins = set(per_origin)
        for entry in frontier.values():
            if not entry["live"]:
                continue
            url = entry["url"]
            origin = _origin(url)
            choices: list[str] = []
            if origin not in seen_origins:
                choices.append(origin)
                seen_origins.add(origin)
            content_type = str(entry.get("content_type") or "").lower()
            if "html" in content_type and 200 <= int(entry.get("status_code") or 0) < 400:
                choices.append(url)
            for candidate in choices:
                if (
                    candidate not in crawled
                    and candidate not in seeds
                    and per_origin[origin] < MAX_KATANA_SEEDS_PER_ORIGIN
                ):
                    seeds.append(candidate)
                    per_origin[origin] += 1
        return seeds

    def _crawl(
        self,
        policy: ScopePolicy,
        state: dict[str, Any],
        seeds: list[str],
        round_number: int,
    ) -> tuple[Any, list[str]]:
        name = f"discovery-katana-r{round_number}"
        remote = self.adapter._copy_lines_input(state, f"{name}-input.txt", seeds)
        args = [
            "katana", "-list", remote, "-silent", "-d", "1", "-jc",
            "-c", "1", "-rl", "5",
        ]
        for pattern in _katana_scope_regexes(policy):
            args.extend(["-cs", pattern])
        result = self.adapter.backend.run(args, process_timeout=900)
        self.adapter._write_result(state, name, result)
        return result, _unique_lines(result.stdout)

    def _write_queue(
        self,
        state: dict[str, Any],
        frontier: dict[str, dict[str, Any]],
        crawled: set[str],
    ) -> None:
        path = self.store.run_dir(state["run_id"]) / "parsed" / "url-queue.jsonl"
        lines = []
        for url in sorted(frontier):
            entry = frontier[url]
            status = (
                "crawled" if url in crawled else
                "live" if entry["live"] else
                "probed" if entry["probed"] else
                "queued"
            )
            lines.append(json.dumps(
                {
                    "url": url,
                    "sources": sorted(entry["sources"]),
                    "round": entry["round"],
                    "status": status,
                    "status_code": entry["status_code"],
                    "content_type": entry["content_type"],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ))
        atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))
        self.store.add_artifact(state, path, "url_queue", "url_discovery")

    @staticmethod
    def _set_state(
        state: dict[str, Any],
        frontier: dict[str, dict[str, Any]],
        crawled: set[str],
        rounds: int,
        stop_reason: str,
    ) -> None:
        state["discovery"] = {
            "rounds": rounds,
            "stop_reason": stop_reason,
            "urls": len(frontier),
            "queued": sum(not entry["probed"] for entry in frontier.values()),
            "crawled": sorted(crawled),
        }

    def run(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        run_dir = self.store.run_dir(state["run_id"])
        frontier = self._load_queue(run_dir)
        saved = state.get("discovery") if isinstance(state.get("discovery"), dict) else {}
        rounds = int(saved.get("rounds") or 0)
        crawled = set(saved.get("crawled") or [])

        for source, raw_url in _source_candidates(run_dir):
            self._add(policy, frontier, source, raw_url, 0)

        baseline_probed, baseline_live, baseline_crawled = self._baseline(policy, run_dir)
        crawled.update(baseline_crawled)
        for url, entry in frontier.items():
            entry["probed"] = entry["probed"] or url in baseline_probed
            entry["live"] = entry["live"] or url in baseline_live

        stop_reason = "max_rounds" if rounds >= MAX_ROUNDS else "no_new_candidates"
        self._write_queue(state, frontier, crawled)

        while rounds < MAX_ROUNDS:
            pending = [url for url, entry in frontier.items() if not entry["probed"]]
            if not pending and not self._seeds(frontier, crawled):
                break

            round_number = rounds + 1
            new_count = 0

            if pending:
                result, records = self._probe(state, pending, round_number)
                record_by_url: dict[str, dict[str, Any]] = {}
                for record in records:
                    for url in self._record_urls(policy, record):
                        record_by_url[url] = record
                        new_count += self._add(policy, frontier, "httpx", url, round_number)

                for target in pending:
                    if result.exit_code == 0 or target in record_by_url:
                        self._mark_probed(frontier[target], record_by_url.get(target))
                for url, record in record_by_url.items():
                    if url in frontier:
                        self._mark_probed(frontier[url], record)
                self._write_queue(state, frontier, crawled)

                if result.exit_code != 0:
                    self._set_state(state, frontier, crawled, rounds, "httpx_failed")
                    return ToolOutcome(
                        result.exit_code,
                        f"Discovery stopped in round {round_number}: HTTPX failed",
                        len(frontier),
                        error="httpx_failed",
                    )

            seeds = self._seeds(frontier, crawled)
            if seeds:
                result, discovered = self._crawl(policy, state, seeds, round_number)
                if result.exit_code != 0:
                    self._set_state(state, frontier, crawled, rounds, "katana_failed")
                    return ToolOutcome(
                        result.exit_code,
                        f"Discovery stopped in round {round_number}: Katana failed",
                        len(frontier),
                        error="katana_failed",
                    )
                crawled.update(seeds)
                for raw_url in discovered:
                    new_count += self._add(policy, frontier, "katana", raw_url, round_number)
                self._write_queue(state, frontier, crawled)

            rounds += 1
            if new_count == 0:
                stop_reason = "no_new_candidates"
                break
            stop_reason = "max_rounds" if rounds >= MAX_ROUNDS else "no_new_candidates"

        self._set_state(state, frontier, crawled, rounds, stop_reason)
        self._write_queue(state, frontier, crawled)
        queued = state["discovery"]["queued"]
        return ToolOutcome(
            0,
            f"Discovery queue contains {len(frontier)} URLs; "
            f"ran {rounds}/{MAX_ROUNDS} rounds and left {queued} queued",
            len(frontier),
        )
