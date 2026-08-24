"""Bounded URL discovery rounds fed by existing recon artifacts."""

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
    host = str(parsed.hostname).lower()
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _source_candidates(
    run_dir: Path,
) -> Iterator[tuple[str, str, str]]:
    # 현재 애플리케이션에서 직접 찾은 경로를 오래된 Wayback URL보다 먼저 보존한다.
    artifact = "parsed/source-endpoints.json"
    for item in _json(run_dir / artifact, []):
        if isinstance(item, dict) and item.get("endpoint"):
            yield "source", str(item["endpoint"]), artifact

    artifact = "parsed/robots.json"
    for document in _json(run_dir / artifact, []):
        if not isinstance(document, dict):
            continue
        robots_url = str(document.get("url") or "")
        for directive in document.get("directives", []):
            if not isinstance(directive, dict):
                continue
            name = str(directive.get("name") or "").lower()
            value = str(directive.get("value") or "").strip()
            if not value:
                continue
            if name == "sitemap":
                yield "robots", value, artifact
            elif name in {"allow", "disallow"} and value.startswith("/") and not any(
                marker in value for marker in ("*", "$")
            ):
                yield "robots", urljoin(robots_url, value), artifact

    for source, artifact in (
        ("katana", "parsed/katana-urls.txt"),
        ("wayback", "parsed/wayback-urls.txt"),
    ):
        path = run_dir / artifact
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        for value in lines:
            if value.strip():
                yield source, value.strip(), artifact


class DiscoveryRunner:
    def __init__(self, adapter: Any, store: RunStore) -> None:
        self.adapter = adapter
        self.store = store

    def _replay(
        self, state: dict[str, Any]
    ) -> tuple[
        dict[str, dict[str, Any]],
        dict[int, str | None],
        Counter[tuple[str, int]],
        set[str],
    ]:
        frontier: dict[str, dict[str, Any]] = {}
        rounds: dict[int, str | None] = {}
        attempts: Counter[tuple[str, int]] = Counter()
        crawled: set[str] = set()
        for event in self.store.events(state["run_id"]):
            event_type = event.get("type")
            if event_type == "discovery_round_started":
                rounds.setdefault(int(event.get("round") or 0), None)
            elif event_type == "discovery_round_finished":
                round_number = int(event.get("round") or 0)
                rounds[round_number] = str(event.get("reason") or "")
            elif event_type == "discovery_command_started":
                round_number = int(event.get("round") or 0)
                rounds.setdefault(round_number, None)
                key = (str(event.get("command") or ""), round_number)
                attempts[key] += 1
            url = event.get("url")
            if not isinstance(url, str):
                continue
            if event_type == "url_discovered":
                entry = frontier.setdefault(
                    url,
                    {
                        "url": url,
                        "sources": set(),
                        "round": int(event.get("round") or 0),
                        "probed": False,
                        "live": False,
                        "status_code": None,
                        "content_type": None,
                    },
                )
                source = event.get("source")
                if isinstance(source, str):
                    entry["sources"].add(source)
            elif url in frontier and event_type == "url_probed":
                entry = frontier[url]
                entry["probed"] = True
                entry["live"] = entry["live"] or bool(event.get("live"))
                entry["status_code"] = event.get("status_code")
                entry["content_type"] = event.get("content_type")
            elif event_type == "url_crawled":
                crawled.add(url)
        rounds.pop(0, None)
        return frontier, rounds, attempts, crawled

    def _add(
        self,
        policy: ScopePolicy,
        state: dict[str, Any],
        frontier: dict[str, dict[str, Any]],
        source: str,
        raw_url: str,
        round_number: int,
        limited: Counter[tuple[str, str]],
        provenance: dict[str, Any] | None = None,
    ) -> bool:
        url = _canonical_url(policy, raw_url)
        if url is None:
            limited[(source, "out_of_scope_or_invalid")] += 1
            return False
        is_new = url not in frontier
        if not is_new and source in frontier[url]["sources"]:
            return False
        if is_new:
            if len(frontier) >= MAX_URLS:
                limited[(source, "total_limit")] += 1
                return False
            if (
                sum(1 for item in frontier if _origin(item) == _origin(url))
                >= MAX_URLS_PER_ORIGIN
            ):
                limited[(source, "origin_limit")] += 1
                return False
            frontier[url] = {
                "url": url,
                "sources": set(),
                "round": round_number,
                "probed": False,
                "live": False,
                "status_code": None,
                "content_type": None,
            }
        frontier[url]["sources"].add(source)
        self.store.append_event(
            state,
            "url_discovered",
            url=url,
            raw_url=raw_url,
            source=source,
            round=round_number,
            **(provenance or {}),
        )
        return is_new

    def _baseline(self, policy: ScopePolicy, run_dir: Path) -> tuple[set[str], set[str], set[str]]:
        probed: set[str] = set()
        live: set[str] = set()
        crawled: set[str] = set()

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
            for item in _httpx_records(
                (run_dir / "raw" / name).read_text(encoding="utf-8")
                if (run_dir / "raw" / name).exists()
                else ""
            ):
                for key in ("input", "url", "final_url"):
                    value = item.get(key)
                    if isinstance(value, str) and (url := _canonical_url(policy, value)):
                        probed.add(url)
        for value in _lines(run_dir / "raw" / "katana-input.txt"):
            if url := _canonical_url(policy, value):
                crawled.add(url)
        return probed, live, crawled

    def _attempt_name(
        self,
        state: dict[str, Any],
        command: str,
        round_number: int,
        attempts: Counter[tuple[str, int]],
    ) -> str:
        key = (command, round_number)
        attempts[key] += 1
        attempt = attempts[key]
        self.store.append_event(
            state,
            "discovery_command_started",
            command=command,
            round=round_number,
            attempt=attempt,
        )
        return f"discovery-{command}-r{round_number}-a{attempt}"

    def _probe(
        self,
        state: dict[str, Any],
        targets: list[str],
        round_number: int,
        attempts: Counter[tuple[str, int]],
    ) -> tuple[Any, list[dict[str, Any]], str]:
        name = self._attempt_name(state, "httpx", round_number, attempts)
        remote = self.adapter._copy_lines_input(state, f"{name}-input.txt", targets)
        result = self.adapter.backend.run(
            [
                "httpx",
                "-l",
                remote,
                "-silent",
                "-j",
                "-sc",
                "-ct",
                "-cl",
                "-duc",
            ],
            process_timeout=900,
        )
        self.adapter._write_result(state, name, result, extension="jsonl")
        return result, _httpx_records(result.stdout), name

    def _crawl(
        self,
        policy: ScopePolicy,
        state: dict[str, Any],
        seeds: list[str],
        round_number: int,
        attempts: Counter[tuple[str, int]],
    ) -> tuple[Any, list[str], str]:
        name = self._attempt_name(state, "katana", round_number, attempts)
        remote = self.adapter._copy_lines_input(state, f"{name}-input.txt", seeds)
        args = [
            "katana", "-list", remote, "-silent", "-d", "1", "-jc",
            "-c", "1", "-rl", "5",
        ]
        for pattern in _katana_scope_regexes(policy):
            args.extend(["-cs", pattern])
        result = self.adapter.backend.run(args, process_timeout=900)
        self.adapter._write_result(state, name, result)
        return result, _unique_lines(result.stdout), name

    @staticmethod
    def _record_urls(policy: ScopePolicy, record: dict[str, Any]) -> list[str]:
        values: list[str] = []
        for key in ("input", "url", "final_url"):
            value = record.get(key)
            if isinstance(value, str) and (url := _canonical_url(policy, value)):
                if url not in values:
                    values.append(url)
        return values

    def _mark_probed(
        self,
        state: dict[str, Any],
        entry: dict[str, Any],
        round_number: int,
        record: dict[str, Any] | None,
    ) -> None:
        try:
            status_code = int((record or {}).get("status_code") or 0)
        except (TypeError, ValueError):
            status_code = 0
        live = bool(record) and status_code > 0 and not (record or {}).get("error")
        content_type = (record or {}).get("content_type")
        entry["probed"] = True
        entry["live"] = entry["live"] or live
        entry["status_code"] = status_code or None
        entry["content_type"] = content_type
        self.store.append_event(
            state,
            "url_probed",
            url=entry["url"],
            round=round_number,
            live=live,
            status_code=status_code or None,
            content_type=content_type,
        )

    def _seeds(
        self,
        frontier: dict[str, dict[str, Any]],
        crawled: set[str],
    ) -> list[str]:
        seeds: list[str] = []
        per_origin = Counter(_origin(url) for url in crawled)
        origins = set(per_origin)
        for entry in frontier.values():
            if not entry["live"]:
                continue
            url = entry["url"]
            origin = _origin(url)
            choices = []
            if origin not in origins:
                choices.append(origin)
                origins.add(origin)
            content_type = str(entry.get("content_type") or "").lower()
            status_code = int(entry.get("status_code") or 0)
            if "html" in content_type and 200 <= status_code < 400:
                choices.append(url)
            for candidate in choices:
                if (
                    candidate in crawled
                    or candidate in seeds
                    or per_origin[origin] >= MAX_KATANA_SEEDS_PER_ORIGIN
                ):
                    continue
                seeds.append(candidate)
                per_origin[origin] += 1
        return seeds

    def _write_queue(
        self,
        state: dict[str, Any],
        frontier: dict[str, dict[str, Any]],
        crawled: set[str],
    ) -> Path:
        path = self.store.run_dir(state["run_id"]) / "parsed" / "url-queue.jsonl"
        lines = []
        for url in sorted(frontier):
            entry = frontier[url]
            status = (
                "crawled"
                if url in crawled
                else "live"
                if entry["live"]
                else "probed"
                if entry["probed"]
                else "queued"
            )
            lines.append(
                json.dumps(
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
                )
            )
        atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))
        self.store.add_artifact(state, path, "url_queue", "url_discovery")
        return path

    def run(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        run_dir = self.store.run_dir(state["run_id"])
        frontier, rounds, attempts, crawled_urls = self._replay(state)
        limited: Counter[tuple[str, str]] = Counter()
        for source, raw_url, artifact in _source_candidates(run_dir):
            self._add(
                policy,
                state,
                frontier,
                source,
                raw_url,
                0,
                limited,
                {"artifact": artifact},
            )

        baseline_probed, baseline_live, baseline_crawled = self._baseline(policy, run_dir)
        for url, entry in frontier.items():
            is_live = url in baseline_live
            if (url in baseline_probed and not entry["probed"]) or (
                is_live and not entry["live"]
            ):
                entry["probed"] = True
                entry["live"] = entry["live"] or is_live
                self.store.append_event(
                    state,
                    "url_probed",
                    url=url,
                    round=0,
                    live=entry["live"],
                    status_code=None,
                    content_type=None,
                    source="baseline",
                    artifact=(
                        "parsed/alive-urls.txt" if is_live else "parsed/httpx.json"
                    ),
                )
            if url in baseline_crawled and url not in crawled_urls:
                crawled_urls.add(url)
                self.store.append_event(
                    state,
                    "url_crawled",
                    url=url,
                    round=0,
                    source="baseline",
                    artifact="raw/katana-input.txt",
                )

        stop_reason = "no_new_candidates"
        exit_code = 0

        def finish_round(round_number: int, reason: str) -> None:
            self.store.append_event(
                state,
                "discovery_round_finished",
                round=round_number,
                reason=reason,
            )
            rounds[round_number] = reason

        while True:
            pending = [
                url for url, entry in frontier.items() if not entry["probed"]
            ]
            seeds = self._seeds(frontier, crawled_urls)
            unfinished = sorted(
                round_number
                for round_number, reason in rounds.items()
                if reason is None
            )

            if not pending and not seeds:
                if unfinished:
                    finish_round(unfinished[0], "no_new_candidates")
                stop_reason = "no_new_candidates"
                break

            if unfinished:
                round_number = unfinished[0]
            else:
                round_number = max(rounds, default=0) + 1
                if round_number > MAX_ROUNDS:
                    stop_reason = "max_rounds"
                    if rounds.get(MAX_ROUNDS) in {"httpx_failed", "katana_failed"}:
                        exit_code = 1
                    break
                rounds[round_number] = None

            new_count = 0

            if pending:
                probe_result, records, probe_name = self._probe(
                    state, pending, round_number, attempts
                )
                exit_code = probe_result.exit_code
                record_by_url: dict[str, dict[str, Any]] = {}
                for record in records:
                    for url in self._record_urls(policy, record):
                        record_by_url[url] = record

                if probe_result.exit_code == 0:
                    for target in pending:
                        self._mark_probed(
                            state,
                            frontier[target],
                            round_number,
                            record_by_url.get(target),
                        )
                else:
                    for target in pending:
                        if target in record_by_url:
                            self._mark_probed(
                                state,
                                frontier[target],
                                round_number,
                                record_by_url[target],
                            )

                for line_number, record in enumerate(records, start=1):
                    provenance = {
                        "artifact": f"raw/{probe_name}.jsonl",
                        "line": line_number,
                    }
                    for url in self._record_urls(policy, record):
                        if self._add(
                            policy,
                            state,
                            frontier,
                            "httpx",
                            url,
                            round_number,
                            limited,
                            provenance,
                        ):
                            new_count += 1
                        if url in frontier and not frontier[url]["probed"]:
                            self._mark_probed(
                                state, frontier[url], round_number, record
                            )

                if probe_result.exit_code != 0:
                    stop_reason = "httpx_failed"
                    finish_round(round_number, stop_reason)
                    break

            accepted_seeds = self._seeds(frontier, crawled_urls)
            if accepted_seeds:
                crawl_result, discovered, crawl_name = self._crawl(
                    policy,
                    state,
                    accepted_seeds,
                    round_number,
                    attempts,
                )
                exit_code = crawl_result.exit_code
                if crawl_result.exit_code == 0:
                    for seed in accepted_seeds:
                        crawled_urls.add(seed)
                        self.store.append_event(
                            state,
                            "url_crawled",
                            url=seed,
                            round=round_number,
                        )
                    for line_number, raw_url in enumerate(discovered, start=1):
                        if self._add(
                            policy,
                            state,
                            frontier,
                            "katana",
                            raw_url,
                            round_number,
                            limited,
                            {
                                "artifact": f"raw/{crawl_name}.log",
                                "line": line_number,
                            },
                        ):
                            new_count += 1
                else:
                    stop_reason = "katana_failed"
                    finish_round(round_number, stop_reason)
                    break

            finish_round(round_number, "complete")
            if new_count == 0:
                stop_reason = "no_new_candidates"
                break
            if round_number >= MAX_ROUNDS:
                stop_reason = "max_rounds"
                break

        for (source, reason), count in sorted(limited.items()):
            self.store.append_event(
                state,
                "frontier_limited",
                source=source,
                reason=reason,
                count=count,
            )

        self._write_queue(state, frontier, crawled_urls)
        queued = sum(1 for item in frontier.values() if not item["probed"])
        rounds_run = max(rounds, default=0)
        state["discovery"] = {
            "rounds": rounds_run,
            "stop_reason": stop_reason,
            "urls": len(frontier),
            "queued": queued,
            "limits": {
                "rounds": MAX_ROUNDS,
                "urls": MAX_URLS,
                "urls_per_origin": MAX_URLS_PER_ORIGIN,
                "katana_seeds_per_origin": MAX_KATANA_SEEDS_PER_ORIGIN,
            },
        }
        return ToolOutcome(
            exit_code,
            (
                f"Discovery queue contains {len(frontier)} URLs; "
                f"ran {rounds_run}/{MAX_ROUNDS} rounds and left {queued} queued"
            ),
            len(frontier),
            error="" if exit_code == 0 else stop_reason,
        )
