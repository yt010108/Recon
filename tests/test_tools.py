from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.docker_backend import CommandResult
from recon_harness.policy import ScopePolicy
from recon_harness.storage import RunStore
from recon_harness.tools import (
    ToolRunner,
    _candidate_source_urls,
    _extract_c_style_comments,
    _extract_html_comments,
    _extract_hidden_content,
    _extract_source_endpoints,
    _response_body,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SCOPE = PROJECT_ROOT / "tests" / "fixtures" / "example.toml"


class FakeBackend:
    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.commands: list[list[str]] = []

    def prepare_remote_dir(self, _run_id: str) -> str:
        return "/work/run/.worker-inputs"

    def copy_to(self, _local: Path, _remote: str) -> None:
        return None

    def run(self, command: list[str], **_kwargs: object) -> CommandResult:
        self.commands.append(command)
        return self.results.pop(0)


def result_with_record(record: dict[str, object]) -> CommandResult:
    return CommandResult(
        exit_code=0,
        stdout=json.dumps(record, ensure_ascii=False) + "\n",
        stderr="",
    )


class ParserTests(unittest.TestCase):
    def test_source_endpoint_patterns_are_extracted_offline(self) -> None:
        source = """fetch('/api/orders?id=1', {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: 'paid', userId: 7})})
<form action="/login" method="post"><input name="username" required><input name="password" type="password"></form>
const action_id = 'abc123';
axios.post("https://example.com/graphql")"""
        findings = _extract_source_endpoints(source)
        self.assertEqual(
            {(item["kind"], item["value"]) for item in findings},
            {
                ("api-path", "/api/orders?id=1"),
                ("request", "/api/orders?id=1"),
                ("form-action", "/login"),
                ("action-id", "abc123"),
                ("request", "https://example.com/graphql"),
            },
        )
        fetch = next(item for item in findings if item["kind"] == "request" and item["value"].startswith("/api/orders"))
        self.assertEqual(fetch["method"], "PATCH")
        self.assertEqual(fetch["query_parameters"], ["id"])
        self.assertEqual(fetch["body_parameters"], ["status", "userId"])
        self.assertEqual(fetch["content_type"], "application/json")
        form = next(item for item in findings if item["kind"] == "form-action")
        self.assertEqual(form["method"], "POST")
        self.assertEqual(form["body_parameters"], ["username", "password"])
        self.assertTrue(form["form_fields"][0]["required"])

    def test_form_without_action_targets_current_document_later(self) -> None:
        findings = _extract_source_endpoints('<form><input name="q"></form>')
        self.assertEqual(findings[0]["value"], "")
        self.assertEqual(findings[0]["method"], "GET")
        self.assertEqual(findings[0]["query_parameters"], ["q"])
    def test_response_body_removes_http_headers(self) -> None:
        record = {"response": "HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nbody\ntext"}
        self.assertEqual(_response_body(record), "body\ntext")

    def test_html_css_and_javascript_comments_are_verbatim(self) -> None:
        source = """<!-- keep <raw> -->
<script>const u = "https://example.test/x"; // js 원문
/* js block\nsecond */</script>
<style>.x { background:url("https://cdn.test/x"); } /* css raw */</style>"""
        comments = _extract_html_comments(source)
        self.assertEqual(comments[0]["text"], " keep <raw> ")
        self.assertEqual(comments[1]["text"], " js 원문")
        self.assertEqual(comments[2]["text"], " js block\nsecond ")
        self.assertEqual(comments[3]["text"], " css raw ")
        self.assertEqual(len(comments), 4)

    def test_c_style_parser_does_not_treat_url_in_string_as_comment(self) -> None:
        comments = _extract_c_style_comments(
            'const url = "https://example.test"; // actual', "javascript"
        )
        self.assertEqual([item["text"] for item in comments], [" actual"])
        self.assertEqual(
            _extract_c_style_comments(
                ".x { background: url(https://cdn.example/x.png); }", "css"
            ),
            [],
        )

    def test_html_and_embedded_js_hidden_content_is_extracted(self) -> None:
        source = """<input type="hidden" name="csrf" value="abc">
<section hidden id="admin"></section>
<div style="display: none" data-path="/internal"></div>
<script>panel.hidden = true; node.style.visibility = 'hidden';</script>"""
        findings = _extract_hidden_content(source, "html")
        self.assertEqual(len(findings), 5)
        self.assertEqual(findings[0]["name"], "csrf")
        self.assertEqual(findings[0]["value"], "abc")
        self.assertEqual(findings[1]["id"], "admin")
        self.assertIn("js-hidden-property", {item["kind"] for item in findings})
        self.assertIn("js-visibility-hidden", {item["kind"] for item in findings})

    def test_javascript_hidden_content_is_extracted(self) -> None:
        findings = _extract_hidden_content(
            "el.setAttribute('hidden', ''); const config = {type: 'hidden'};", "javascript"
        )
        self.assertEqual(
            {item["kind"] for item in findings},
            {"js-set-hidden", "js-hidden-input"},
        )

    def test_source_candidates_stay_in_scope_and_skip_binary(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        values = [
            "https://example.com/",
            "https://example.com/app.js?v=1#fragment",
            "https://example.com/logo.png",
            "https://example.net/app.js",
            "https://example.com/logout/app.js",
        ]
        self.assertEqual(
            _candidate_source_urls(policy, values),
            [
                "https://example.com/",
                "https://example.com/app.js?v=1",
                "https://example.com/logout/app.js",
            ],
        )


class AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = RunStore(Path(self.temporary.name) / "runs")
        self.policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        self.state = self.store.create(self.policy.path, self.policy.snapshot())

    def test_robots_adapter_keeps_comment_original_but_sanitizes_raw_log(self) -> None:
        body = "User-agent: *\nDisallow: /admin\n# token=sample-original-value\n"
        record = {
            "url": "http://recon-juice-shop:3000/robots.txt",
            "status_code": 200,
            "content_type": "text/plain",
            "response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body,
        }
        backend = FakeBackend(result_with_record(record))
        ToolRunner(backend, self.store).run_robots_txt(
            self.policy, self.state
        )
        run_dir = self.store.run_dir(self.state["run_id"])
        parsed = json.loads((run_dir / "parsed" / "robots.json").read_text(encoding="utf-8"))
        self.assertEqual(parsed[0]["body"], body)
        self.assertEqual(parsed[0]["comments"][0]["text"], " token=sample-original-value")
        self.assertNotIn(
            "sample-original-value",
            (run_dir / "raw" / "robots_txt.jsonl").read_text(encoding="utf-8"),
        )
        self.assertNotIn("-fr", backend.commands[0])

    def test_dorkgen_writes_queries_without_backend_calls(self) -> None:
        backend = FakeBackend()
        outcome = ToolRunner(backend, self.store).run_dorkgen(self.policy, self.state)
        path = self.store.run_dir(self.state["run_id"]) / "parsed" / "google-dorks.txt"
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertGreater(len(lines), 50)
        self.assertEqual(lines[0], "site:recon-juice-shop")
        self.assertEqual(outcome.item_count, len(lines))
        self.assertEqual(backend.commands, [])

    def test_source_adapter_keeps_exact_multiline_comment(self) -> None:
        run_dir = self.store.run_dir(self.state["run_id"])
        (run_dir / "parsed" / "alive-urls.txt").write_text(
            "http://recon-juice-shop:3000/\n", encoding="utf-8"
        )
        (run_dir / "parsed" / "katana-urls.txt").write_text(
            "http://recon-juice-shop:3000/app.js\n", encoding="utf-8"
        )
        source = "fetch('/api/orders?id=1');\nconst action_id = 'abc123';\npanel.hidden = true;\n/* secret=VISIBLE\nsecond line */"
        record = {
            "url": "http://recon-juice-shop:3000/app.js",
            "status_code": 200,
            "content_type": "application/javascript",
            "response": "HTTP/1.1 200 OK\r\n\r\n" + source,
        }
        backend = FakeBackend(result_with_record(record))
        ToolRunner(backend, self.store).run_source_comments(
            self.policy, self.state
        )
        parsed = json.loads(
            (run_dir / "parsed" / "source-comments.json").read_text(encoding="utf-8")
        )
        self.assertEqual(parsed[0]["text"], " secret=VISIBLE\nsecond line ")
        endpoints = json.loads(
            (run_dir / "parsed" / "source-endpoints.json").read_text(encoding="utf-8")
        )
        self.assertTrue(any(item.get("endpoint", "").endswith("/api/orders?id=1") for item in endpoints))
        self.assertTrue(any(item["kind"] == "action-id" and item["value"] == "abc123" for item in endpoints))
        hidden = json.loads(
            (run_dir / "parsed" / "source-hidden.json").read_text(encoding="utf-8")
        )
        self.assertEqual(hidden[0]["kind"], "js-hidden-property")
        self.assertEqual(hidden[0]["source"], "http://recon-juice-shop:3000/app.js")
        self.assertNotIn(
            "VISIBLE",
            (run_dir / "raw" / "source_comments.jsonl").read_text(encoding="utf-8"),
        )
        self.assertNotIn("-fr", backend.commands[0])

    def test_assetfinder_merges_sorted_unique_and_filters_scope(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        state = self.store.create(policy.path, policy.snapshot())
        stdout = (
            "b.example.com\n"
            "*.example.com\n"
            "a.example.com\n"
            "evil-example.com\n"
            "status.example.com\n"
            "b.example.com\n"
        )
        backend = FakeBackend(CommandResult(0, stdout, ""))
        outcome = ToolRunner(backend, self.store).run_assetfinder(
            policy, state
        )
        hosts_path = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        self.assertEqual(
            hosts_path.read_text(encoding="utf-8").splitlines(),
            ["a.example.com", "b.example.com", "example.com", "status.example.com"],
        )
        self.assertEqual(outcome.item_count, 4)

    def test_subfinder_and_assetfinder_merge_into_one_hosts_file(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        state = self.store.create(policy.path, policy.snapshot())
        subfinder_out = CommandResult(0, "c.example.com\n", "")
        assetfinder_out = CommandResult(0, "c.example.com\nd.example.com\n", "")
        runner = ToolRunner(FakeBackend(subfinder_out), self.store)
        runner.run_subfinder(policy, state)
        runner.backend = FakeBackend(assetfinder_out)
        runner.run_assetfinder(policy, state)
        hosts_path = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        self.assertEqual(
            hosts_path.read_text(encoding="utf-8").splitlines(),
            ["c.example.com", "d.example.com", "example.com"],
        )

    def test_amass_enum_is_passive_only_and_merges_hosts(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        state = self.store.create(policy.path, policy.snapshot())
        stdout = "e.example.com\n*.example.com\nfake-example.org\ne.example.com\n"
        backend = FakeBackend(
            CommandResult(0, stdout, "")
        )
        outcome = ToolRunner(backend, self.store).run_amass_enum(policy, state)
        self.assertEqual(
            backend.commands[0],
            ["amass", "enum", "-passive", "-d", "example.com"],
        )
        hosts_path = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        self.assertEqual(
            hosts_path.read_text(encoding="utf-8").splitlines(),
            ["e.example.com", "example.com"],
        )
        self.assertEqual(outcome.item_count, 2)

    def test_nuclei_uses_plain_command_and_keeps_jsonl_findings(self) -> None:
        run_dir = self.store.run_dir(self.state["run_id"])
        (run_dir / "parsed" / "alive-urls.txt").write_text(
            "http://recon-juice-shop:3000/\nhttp://outside.test/\n",
            encoding="utf-8",
        )
        in_scope = {
            "template-id": "test-header",
            "info": {"name": "Test Header", "severity": "low"},
            "type": "http",
            "matched-at": "http://recon-juice-shop:3000/",
            "matcher-name": "header",
            "request": "GET / HTTP/1.1\r\nHost: recon-juice-shop:3000\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nbody",
        }
        out_of_scope = dict(in_scope, **{"matched-at": "http://outside.test/"})
        no_evidence = dict(in_scope, **{"template-id": "no-response"})
        no_evidence.pop("response")
        backend = FakeBackend(
            CommandResult(
                0,
                "\n".join(json.dumps(item) for item in (in_scope, out_of_scope, no_evidence)) + "\n",
                "",
            )
        )

        outcome = ToolRunner(backend, self.store).run_nuclei(self.policy, self.state)

        command = backend.commands[0]
        for option in (
            "-disable-unsigned-templates", "-disable-redirects", "-no-interactsh",
            "-tags", "-exclude-tags", "-rate-limit", "-concurrency", "-bulk-size",
            "-timeout", "-type",
        ):
            self.assertNotIn(option, command)
        findings = json.loads(
            (run_dir / "parsed" / "nuclei-findings.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["status_code"], 200)
        self.assertEqual(findings[0]["evidence"], "raw/nuclei.jsonl:1")
        self.assertEqual(findings[1]["matched_at"], "http://outside.test/")
        self.assertIsNone(findings[2]["status_code"])
        self.assertEqual(outcome.item_count, 3)


if __name__ == "__main__":
    unittest.main()
