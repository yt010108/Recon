from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.deep_discovery import DeepDiscoveryToolRunner
from recon_harness.discovery import DiscoveryRunner
from recon_harness.docker_backend import CommandResult
from recon_harness.policy import ScopePolicy
from recon_harness.storage import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FakeBackend:
    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.commands: list[list[str]] = []

    def prepare_remote_dir(self, _run_id: str) -> str:
        return "/work/run/.worker-inputs"

    def copy_to(self, _local: Path, _remote: str) -> None:
        pass

    def run(self, command: list[str], **_kwargs: object) -> CommandResult:
        self.commands.append(command)
        if not self.results:
            raise AssertionError(f"unexpected command: {command}")
        return self.results.pop(0)


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
    def _queue(run_dir: Path) -> dict[str, dict]:
        return {
            item["url"]: item
            for item in (
                json.loads(line)
                for line in (run_dir / "discovery" / "url-queue.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            )
        }

    def test_sources_merge_scope_and_provenance(self) -> None:
        policy, store, state, run_dir = self._run()
        (run_dir / "crawl" / "source-endpoints.json").write_text(
            json.dumps([{"endpoint": "http://recon-juice-shop:3000/api/users"}]),
            encoding="utf-8",
        )
        (run_dir / "probe" / "robots.json").write_text(
            json.dumps(
                [
                    {
                        "url": "http://recon-juice-shop:3000/robots.txt",
                        "directives": [
                            {"name": "allow", "value": "/admin"},
                            {"name": "disallow", "value": "/private/*"},
                        ],
                    }
                ]
            ),
            encoding="utf-8",
        )
        (run_dir / "crawl" / "katana-urls.txt").write_text(
            "http://recon-juice-shop:3000/api/users\n", encoding="utf-8"
        )
        (run_dir / "collect" / "wayback-urls.txt").write_text(
            "http://recon-juice-shop:3000/old\nhttps://outside.example/path\n",
            encoding="utf-8",
        )

        outcome = DiscoveryRunner(
            DeepDiscoveryToolRunner(FakeBackend(CommandResult(0, "", "")), store),
            store,
        ).run(policy, state)

        queue = self._queue(run_dir)
        self.assertEqual(queue["http://recon-juice-shop:3000/api/users"]["sources"], ["katana", "source"])
        self.assertIn("http://recon-juice-shop:3000/admin", queue)
        self.assertIn("http://recon-juice-shop:3000/old", queue)
        self.assertFalse(any("outside.example" in url for url in queue))
        self.assertEqual(outcome.exit_code, 0)

    def test_stops_after_two_successful_rounds(self) -> None:
        policy, store, state, run_dir = self._run()
        start = "http://recon-juice-shop:3000/start"
        middle = "http://recon-juice-shop:3000/middle"
        last = "http://recon-juice-shop:3000/last"
        (run_dir / "collect" / "wayback-urls.txt").write_text(start + "\n", encoding="utf-8")
        backend = FakeBackend(
            CommandResult(0, _record(start) + "\n", ""),
            CommandResult(0, middle + "\n", ""),
            CommandResult(0, _record(middle) + "\n", ""),
            CommandResult(0, last + "\n", ""),
        )

        DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(policy, state)

        self.assertEqual(state["discovery"]["rounds"], 2)
        self.assertEqual(state["discovery"]["stop_reason"], "max_rounds")
        self.assertEqual(self._queue(run_dir)[last]["status"], "queued")
        self.assertEqual([command[0] for command in backend.commands], ["httpx", "katana", "httpx", "katana"])

    def test_failed_katana_retries_same_round_without_reprobing(self) -> None:
        policy, store, state, run_dir = self._run()
        page = "http://recon-juice-shop:3000/page"
        (run_dir / "collect" / "wayback-urls.txt").write_text(page + "\n", encoding="utf-8")

        first = FakeBackend(
            CommandResult(0, _record(page) + "\n", ""),
            CommandResult(1, "", "katana failed"),
        )
        outcome = DiscoveryRunner(DeepDiscoveryToolRunner(first, store), store).run(policy, state)
        self.assertEqual(outcome.exit_code, 1)
        self.assertEqual(state["discovery"]["rounds"], 0)
        store.save(state)

        resumed = store.load(state["run_id"])
        second = FakeBackend(CommandResult(0, "", ""))
        outcome = DiscoveryRunner(DeepDiscoveryToolRunner(second, store), store).run(policy, resumed)

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(resumed["discovery"]["rounds"], 1)
        self.assertEqual([command[0] for command in second.commands], ["katana"])
        self.assertTrue((run_dir / "discovery" / "raw" / "discovery-katana-r1.log").is_file())

    def test_katana_seed_limit_applies_to_run(self) -> None:
        policy, store, state, run_dir = self._run()
        pages = [f"http://recon-juice-shop:3000/page-{i}" for i in range(4)]
        (run_dir / "collect" / "wayback-urls.txt").write_text("\n".join(pages) + "\n", encoding="utf-8")
        backend = FakeBackend(
            CommandResult(0, "\n".join(_record(page) for page in pages) + "\n", ""),
            CommandResult(0, "", ""),
        )

        DiscoveryRunner(DeepDiscoveryToolRunner(backend, store), store).run(policy, state)

        seeds = (run_dir / "discovery" / "raw" / "discovery-katana-r1-input.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(seeds), 3)


if __name__ == "__main__":
    unittest.main()
