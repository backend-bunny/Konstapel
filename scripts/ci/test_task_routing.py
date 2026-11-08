"""Routing must never silently downgrade a critical task or accept broken metadata."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("routing", ROOT / "scripts/agents/select-task.py")
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)


class TaskRoutingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / ".claude").mkdir()
        (self.root / ".claude/task-routing.json").write_bytes((ROOT / ".claude/task-routing.json").read_bytes())
        self.path = self.root / "openspec/changes/example/tasks.md"
        self.path.parent.mkdir(parents=True)
        self.path.write_text('- [ ] 1.1 Bounded work\n- [ ] 1.2 Recovery\n  <!-- agent: tier=deep risk=high reason="Lost commit response" -->\n- [x] 1.3 Done\n')

    def select(self, task="1.1", provider="claude", **kwargs):
        return routing.select(self.root, "example", task, provider, **kwargs)

    def test_defaults_and_provider_mapping(self):
        self.assertEqual(self.select()["model"], "sonnet")
        self.assertTrue(self.select()["defaulted"])
        self.assertIsNone(self.select()["risk"])
        self.assertEqual(self.select(provider="codex")["model"], "gpt-6.1-sol")
        self.assertEqual(self.select("1.2")["model"], "opus")
        self.assertEqual(self.select("1.2", "codex")["model"], "gpt-6-astra")
        self.assertEqual(self.select("1.2")["reason"], "Lost commit response")

    def test_alternatives_and_escalation(self):
        for model in ("gpt-6-sol", "gpt-5.6-terra"):
            self.assertEqual(self.select(provider="codex", model=model)["model"], model)
        result = self.select(provider="codex", escalate=True)
        self.assertEqual(result["model"], "gpt-6-astra")
        self.assertEqual(result["declaredTier"], "standard")
        self.assertTrue(result["escalated"])

    def test_light_is_explicit(self):
        self.path.write_text('- [ ] 1.1 Mechanical edit\n  <!-- agent: tier=light risk=low -->\n')
        self.assertEqual(self.select(provider="codex")["model"], "gpt-6-luna")
        self.assertEqual(self.select()["model"], "sonnet")

    def test_no_downgrade_or_unknown_model(self):
        for task, model in (("1.2", "gpt-6.1-sol"), ("1.1", "gpt-6-luna"), ("1.1", "unknown")):
            with self.subTest(model=model), self.assertRaises(ValueError):
                self.select(task, "codex", model=model)

    def test_completed_missing_and_ordinal_ids_rejected(self):
        for task in ("1.3", "9.9", "2"):
            with self.subTest(task=task), self.assertRaises(ValueError):
                self.select(task)

    def test_malformed_metadata_never_falls_back(self):
        for metadata in ('tier=depe risk=high', 'tier=standard risk=high',
                         'tier=deep', 'tier=deep risk=high tier=standard',
                         'tier=deep risk=high unknown=value', 'tier=deep risk=high reason="broken'):
            self.path.write_text(f'- [ ] 1.1 Work\n  <!-- agent: {metadata} -->\n')
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                self.select()

    def test_orphan_and_duplicate_metadata_rejected(self):
        for text in ('<!-- agent: tier=deep risk=high -->\n- [ ] 1.1 Work\n',
                     '- [ ] 1.1 Work\n\n<!-- agent: tier=deep risk=high -->\n',
                     '- [ ] 1.1 Work\n<!-- agent: tier=deep risk=high -->\n<!-- agent: tier=standard risk=low -->\n',
                     '- [ ] 1.1 Work\n- [ ] 1.1 Duplicate\n'):
            self.path.write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.select()

    def test_examples_in_fences_are_not_tasks(self):
        self.path.write_text('```markdown\n- [ ] 1.1 Example\n<!-- agent: tier=deep risk=high -->\n```\n- [ ] 1.1 Real task\n')
        self.assertEqual(self.select()["description"], "Real task")

    def test_invalid_configuration_rejected(self):
        path = self.root / ".claude/task-routing.json"
        data = json.loads(path.read_text())
        data["providers"]["codex"]["defaults"]["deep"] = "gpt-6-luna"
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.select()

    def test_paths_rejected(self):
        for change in ("../archive/example", "/tmp/example", "archive/example"):
            with self.subTest(change=change), self.assertRaises(ValueError):
                routing.select(self.root, change, "1.1", "claude")

    def test_repository_configuration_and_active_metadata(self):
        routing.config(ROOT)
        for path in (ROOT / "openspec/changes").glob("*/tasks.md"):
            with self.subTest(path=path):
                for task in routing.tasks(path).values():
                    if not task["done"]:
                        self.assertTrue(task["metadata"], f"{path}: unfinished task {task['task']} needs routing metadata")


if __name__ == "__main__":
    unittest.main()
