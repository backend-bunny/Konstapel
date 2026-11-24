"""Bot-opened PRs use the automation App token so their required checks run.

PRs that a workflow creates or updates with GITHUB_TOKEN get pull_request runs
held at approval required, and dispatched runs don't satisfy the required
checks. See docs/releases.md#automation-app.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CONFIGURED = "vars.KONSTAPEL_AUTOMATION_APP_CLIENT_ID != ''"
UNCONFIGURED = "vars.KONSTAPEL_AUTOMATION_APP_CLIENT_ID == ''"
SECRET = "KONSTAPEL_AUTOMATION_APP_PRIVATE_KEY"
TOKEN = "${{ steps.app.outputs.token || github.token }}"
# Workflow -> the action that creates or updates the bot PR.
BOT_PR_WORKFLOWS = {
    "release-please.yml": "googleapis/release-please-action@",
    "lock-refresh.yml": "peter-evans/create-pull-request@",
}


def steps(text: str) -> list[str]:
    """Split a single-job workflow's steps (six-space list items) into blocks."""
    body = text.split("\n    steps:\n", 1)[1]
    body = re.split(r"\n  [a-z][\w-]*:\n", body, maxsplit=1)[0]  # stop at the next job
    return ["      - " + block for block in re.split(r"(?m)^      - ", body)[1:]]


class BotPRTokenTests(unittest.TestCase):
    def test_pr_steps_use_a_narrow_app_token_when_configured(self):
        for name, action in BOT_PR_WORKFLOWS.items():
            with self.subTest(workflow=name):
                blocks = steps((WORKFLOWS / name).read_text())
                app = [i for i, b in enumerate(blocks) if "actions/create-github-app-token@" in b]
                self.assertEqual(len(app), 1)
                block = blocks[app[0]]
                self.assertRegex(block, r"actions/create-github-app-token@[0-9a-f]{40} # v\d")
                self.assertIn("id: app\n", block)
                self.assertIn(f"if: {CONFIGURED}\n", block)
                self.assertIn(f"private-key: ${{{{ secrets.{SECRET} }}}}\n", block)
                self.assertEqual(sorted(re.findall(r"permission-([\w-]+): (\w+)", block)),
                                 [("contents", "write"), ("pull-requests", "write")])
                creators = [i for i, b in enumerate(blocks) if action in b]
                self.assertEqual(len(creators), 1)
                self.assertGreater(creators[0], app[0])
                self.assertIn(f"token: {TOKEN}\n", blocks[creators[0]])

    def test_dispatch_fallback_runs_only_without_the_app(self):
        for name in BOT_PR_WORKFLOWS:
            with self.subTest(workflow=name):
                dispatch = [b for b in steps((WORKFLOWS / name).read_text()) if "gh workflow run" in b]
                self.assertEqual(len(dispatch), 1)
                condition = re.search(r"\n        if: (.*)\n", dispatch[0]).group(1)
                self.assertTrue(condition.endswith(f"&& {UNCONFIGURED}"), condition)

    def test_app_key_is_confined_to_trusted_main_jobs(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text()
            with self.subTest(workflow=path.name):
                self.assertNotIn("pull_request_target", text)
                if path.name in BOT_PR_WORKFLOWS:
                    self.assertEqual(text.count(SECRET), 1)
                    self.assertIn("if: github.ref == 'refs/heads/main'\n", text)
                    self.assertNotRegex(text.split("\njobs:", 1)[0], r"\n  pull_request")
                else:
                    self.assertNotIn(SECRET, text)


if __name__ == "__main__":
    unittest.main()
