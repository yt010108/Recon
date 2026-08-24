from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_harness.deep_discovery import DeepDiscoveryToolRunner
from recon_harness.discovery import DiscoveryRunner
from recon_harness.docker_backend import CommandResult
from recon_harness.policy import ScopePolicy
from recon_harness.storage import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FakeBackend:
    def __init__(self, *results: CommandResult | BaseException) -> None:
        self.results = list(results)
        self.commands: list[list[str]] = []

    def prepare_remote_dir(self, _run_id: str) -> str:
        return "/work/run/.worker-inputs"

    def copy_to(self, _local: Path, _remote: str) -> None:
        return None

    def run(self, command: list[str], **_kwargs: object) -> CommandResult:
        self.commands.append(command)
        if not self.results:
            raise AssertionError(f"unexpected command: {command}")
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def _record(url: str, content_type: str = "text/html") -> str:
    return json.dumps(
        {
            "input": url,
            "url": url,
            "status_code": 200,
            "content_type": content_type,
        }
    )


class DiscoveryTests(unittest.TestCase):
    def _run(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        store = RunStore(Path(temporary.name) / "runs")
        state = store.create(policy.path, policy.snapshot())
        return policy, store, state, store.run_dir(state["run_id"])

    @staticmethod
    def _queue(run_dir: Path) -> list[dict]:
        return [
            json.loads(line)
            for line in (run_dir / "parsed" / "url-queue.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]

    def test_sources_are_merged_with_provenance_and_scope_filter(self) -> None:
        policy, store, state, run_dir = self._run()
        (run_dir / "parsed" / "source-endpoints.json").write_text(
            json.dumps(
                [{"endpoint": "http://recon-juice-shop:3000/api/users"}]
            ),
            encoding="utf-8",
        )
        (run_dir / "parsed" / "robots.json").write_text(
            json.dumps(
                [
                    {
                        "url": "http://recon-juice-shop:3000/robots.txt",
                        "directives": [
                            {"name": "allow", "value": "/admin"},
                            {"name": "disallow", "value": "/private/*"},
                            {
                                "name": "sitemap",
                                "value": "http://recon-juice-shop:3000/sitemap.xml",
                            },
                        ],
                    }
                ]
            ),
            encoding="utf-8",
        )
        (run_dir / "parsed" / "katana-urls.txt").write_text(
            "http://recon-juice-shop:3000/api/users\n",
            encoding="utf-8",
        )
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            "http://recon-juice-shop:3000/old\nhttps://outside.example/path\n",
            encoding="utf-8",
        )
        backend = FakeBackend(CommandResult(0, "", ""))
        outcome = DiscoveryRunner(
            DeepDiscoveryToolRunner(backend, store), store
        ).run(policy, state)

        queue = {item["url"]: item for item in self._queue(run_dir)}
        api = "http://recon-juice-shop:3000/api/users"
        self.assertEqual(queue[api]["sources"], ["katana", "source"])
        self.assertIn("http://recon-juice-shop:3000/admin", queue)
        self.assertIn("http://recon-juice-shop:3000/sitemap.xml", queue)
        self.assertIn("http://recon-juice-shop:3000/old", queue)
        self.assertFalse(any("outside.example" in url for url in queue))
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(state["discovery"]["rounds"], 1)
        self.assertEqual(len(backend.commands), 1)

    def test_recursion_stops_after_two_rounds(self) -> None:
        policy, store, state, run_dir = self._run()
        start = "http://recon-juice-shop:3000/start"
        next_url = "http://recon-juice-shop:3000/next"
        last_url = "http://recon-juice-shop:3000/last"
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            start + "\n", encoding="utf-8"
        )
        backend = FakeBackend(
            CommandResult(0, _record(start) + "\n", ""),
            CommandResult(0, next_url + "\n", ""),
            CommandResult(0, _record(next_url) + "\n", ""),
            CommandResult(0, last_url + "\n", ""),
        )
        DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(
            policy, state
        )

        queue = {item["url"]: item for item in self._queue(run_dir)}
        self.assertEqual(len(backend.commands), 4)
        self.assertEqual(state["discovery"]["rounds"], 2)
        self.assertEqual(state["discovery"]["stop_reason"], "max_rounds")
        self.assertEqual(queue[last_url]["status"], "queued")

    def test_katana_gets_new_origin_and_html_only(self) -> None:
        policy, store, state, run_dir = self._run()
        html = "http://recon-juice-shop:3000/page"
        data = "http://recon-juice-shop:3000/data.json"
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            f"{html}\n{data}\n", encoding="utf-8"
        )
        backend = FakeBackend(
            CommandResult(
                0,
                _record(html) + "\n" + _record(data, "application/json") + "\n",
                "",
            ),
            CommandResult(0, "", ""),
        )
        DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(
            policy, state
        )

        seeds = (
            run_dir / "raw" / "discovery-katana-r1-a1-input.txt"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            seeds,
            ["http://recon-juice-shop:3000/", html],
        )
        self.assertNotIn(data, seeds)
        katana = backend.commands[1]
        self.assertEqual(katana[katana.index("-c") + 1], "1")
        self.assertEqual(katana[katana.index("-rl") + 1], "5")
        self.assertEqual(state["discovery"]["stop_reason"], "no_new_candidates")

    def test_already_probed_url_does_not_run_httpx_again(self) -> None:
        policy, store, state, run_dir = self._run()
        done = "http://recon-juice-shop:3000/done"
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            done + "\n", encoding="utf-8"
        )
        (run_dir / "parsed" / "httpx.json").write_text(
            json.dumps([{"url": done, "status_code": 200}]),
            encoding="utf-8",
        )
        backend = FakeBackend()
        DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(
            policy, state
        )
        self.assertEqual(backend.commands, [])
        self.assertEqual(state["discovery"]["rounds"], 0)

    def test_per_origin_limit_is_recorded(self) -> None:
        policy, store, state, run_dir = self._run()
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            "\n".join(
                f"http://recon-juice-shop:3000/{index}" for index in range(3)
            )
            + "\n",
            encoding="utf-8",
        )
        backend = FakeBackend(CommandResult(0, "", ""))
        with patch("recon_harness.discovery.MAX_URLS_PER_ORIGIN", 2):
            DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(
                policy, state
            )
        self.assertEqual(len(self._queue(run_dir)), 2)
        limited = [
            event
            for event in store.events(state["run_id"])
            if event.get("type") == "frontier_limited"
        ]
        self.assertTrue(
            any(
                event.get("reason") == "origin_limit"
                and event.get("count") == 1
                for event in limited
            )
        )

    def test_katana_failure_resumes_without_reprobing(self) -> None:
        policy, store, state, run_dir = self._run()
        page = "http://recon-juice-shop:3000/page"
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            page + "\n", encoding="utf-8"
        )
        first = FakeBackend(
            CommandResult(0, _record(page) + "\n", ""),
            CommandResult(1, "", "katana failed"),
        )
        first_outcome = DiscoveryRunner(
            DeepDiscoveryToolRunner(first, store), store
        ).run(policy, state)

        resumed = store.load(state["run_id"])
        second = FakeBackend(CommandResult(0, "", ""))
        second_outcome = DiscoveryRunner(
            DeepDiscoveryToolRunner(second, store), store
        ).run(policy, resumed)

        self.assertEqual(first_outcome.exit_code, 1)
        self.assertEqual(second_outcome.exit_code, 0)
        self.assertEqual(len(second.commands), 1)
        self.assertEqual(second.commands[0][0], "katana")
        self.assertEqual(resumed["discovery"]["rounds"], 2)
        self.assertTrue((run_dir / "raw" / "discovery-katana-r1-a1.log").is_file())
        self.assertTrue((run_dir / "raw" / "discovery-katana-r2-a1.log").is_file())

    def test_unfinished_round_resumes_katana_only(self) -> None:
        policy, store, state, run_dir = self._run()
        page = "http://recon-juice-shop:3000/page"
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            page + "\n", encoding="utf-8"
        )
        interrupted = FakeBackend(
            CommandResult(0, _record(page) + "\n", ""),
            RuntimeError("interrupted before katana output"),
        )
        with self.assertRaises(RuntimeError):
            DiscoveryRunner(
                DeepDiscoveryToolRunner(interrupted, store), store
            ).run(policy, state)

        resumed = store.load(state["run_id"])
        backend = FakeBackend(CommandResult(0, "", ""))
        DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(
            policy, resumed
        )

        self.assertEqual(len(backend.commands), 1)
        self.assertEqual(backend.commands[0][0], "katana")
        self.assertEqual(resumed["discovery"]["rounds"], 1)
        self.assertTrue(
            (run_dir / "raw" / "discovery-katana-r1-a1-input.txt").is_file()
        )
        self.assertTrue(
            (run_dir / "raw" / "discovery-katana-r1-a2-input.txt").is_file()
        )

    def test_max_rounds_persist_across_retries(self) -> None:
        policy, store, state, run_dir = self._run()
        page = "http://recon-juice-shop:3000/page"
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            page + "\n", encoding="utf-8"
        )

        for _round in range(2):
            backend = FakeBackend(CommandResult(1, "", "httpx failed"))
            outcome = DiscoveryRunner(
                DeepDiscoveryToolRunner(backend, store), store
            ).run(policy, state)
            self.assertEqual(outcome.exit_code, 1)
            state = store.load(state["run_id"])

        third = FakeBackend()
        outcome = DiscoveryRunner(
            DeepDiscoveryToolRunner(third, store), store
        ).run(policy, state)

        self.assertEqual(outcome.exit_code, 1)
        self.assertEqual(third.commands, [])
        self.assertEqual(state["discovery"]["rounds"], 2)
        self.assertEqual(state["discovery"]["stop_reason"], "max_rounds")

    def test_katana_seed_limit_applies_to_the_whole_run(self) -> None:
        policy, store, state, run_dir = self._run()
        pages = [f"http://recon-juice-shop:3000/page-{index}" for index in range(4)]
        next_page = "http://recon-juice-shop:3000/next"
        (run_dir / "parsed" / "wayback-urls.txt").write_text(
            "\n".join(pages) + "\n", encoding="utf-8"
        )
        backend = FakeBackend(
            CommandResult(0, "\n".join(_record(page) for page in pages) + "\n", ""),
            CommandResult(0, next_page + "\n", ""),
            CommandResult(0, _record(next_page) + "\n", ""),
        )
        DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(
            policy, state
        )

        katana_commands = [command for command in backend.commands if command[0] == "katana"]
        seeds = (
            run_dir / "raw" / "discovery-katana-r1-a1-input.txt"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(katana_commands), 1)
        self.assertEqual(len(seeds), 3)


if __name__ == "__main__":
    unittest.main()
