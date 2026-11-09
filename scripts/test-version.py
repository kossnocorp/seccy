"""Exercise release tasks in disposable repositories; never push to GitHub."""
import datetime
import os
from pathlib import Path
import subprocess
import tempfile
import json
import unittest

ROOT = Path(__file__).resolve().parent.parent
TASKS = {
    name: {"run": json.loads(subprocess.check_output(
        ["mise", "tasks", "info", "//:" + name, "--json"], cwd=ROOT, text=True
    ))["run"][0]}
    for name in ("version:cli", "release:cli", "release:version", "release:website")
}


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.env = dict(os.environ, CARGO_NET_OFFLINE="true", GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL="/dev/null")
        self.git("init", "-q")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release@example.invalid")
        (self.repo / ".gitignore").write_text("/target/\n")
        (self.repo / "Cargo.toml").write_text('''[workspace]
members = ["pkgs/cli", "pkgs/core"]
resolver = "2"
[workspace.package]
version = "0.1.0"
''')
        for name in ("cli", "core"):
            crate = self.repo / "pkgs" / name
            (crate / "src").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(
                f'[package]\nname = "test_{name}"\nversion.workspace = true\nedition = "2021"\n')
            (crate / "src/lib.rs").write_text("")
        self.command("cargo", "generate-lockfile")
        self.git("add", ".")
        self.git("commit", "-qm", "Initial")
        # Nested mise calls execute the actual task body with its parsed argument.
        tools = self.root / "tools"
        tools.mkdir()
        for name, task in TASKS.items():
            if name in ("version:cli", "release:version"):
                (tools / name).write_text(task["run"])
        mise = tools / "mise"
        mise.write_text('#!/bin/bash\nset -eu\nexport usage_version="${3:-}"\nexec bash "' + str(tools) + '/${2#//:}"\n')
        mise.chmod(0o755)
        self.env["PATH"] = str(tools) + os.pathsep + self.env["PATH"]

    def command(self, *args, check=True):
        return subprocess.run(args, cwd=self.repo, env=self.env, text=True,
                              capture_output=True, check=check)

    def git(self, *args):
        return self.command("git", *args).stdout.strip()

    def task(self, name, version="0.2.0"):
        return subprocess.run(["bash", "-c", TASKS[name]["run"]], cwd=self.repo,
                              env=dict(self.env, usage_version=version),
                              text=True, capture_output=True)

    def test_mise_usage_rejects_invalid_versions(self):
        for task in ("version:cli", "release:cli"):
            for version in ("invalid", "1.2", "01.2.3", "1.2.3-rc.1", "1.2.3; echo unsafe"):
                result = subprocess.run(
                    ["mise", "run", "//:" + task, version], cwd=ROOT,
                    text=True, capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Expected a version in X.Y.Z format", result.stderr)

    def test_cli_bumps_shared_version_commits_and_tags(self):
        result = self.task("version:cli")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("log", "-1", "--format=%s"), "Bump cli@0.2.0")
        self.assertEqual(self.git("rev-parse", "cli@0.2.0"), self.git("rev-parse", "HEAD"))
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertIn('version = "0.2.0"', (self.repo / "Cargo.toml").read_text())
        self.assertEqual((self.repo / "Cargo.lock").read_text().count('version = "0.2.0"'), 2)
        before = self.git("rev-parse", "HEAD")
        self.assertNotEqual(self.task("version:cli").returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD"), before)

    def test_dirty_trees_abort(self):
        for kind in ("untracked", "tracked", "staged"):
            with self.subTest(kind=kind):
                path = self.repo / ("new" if kind == "untracked" else "Cargo.toml")
                before = path.read_text() if path.exists() else None
                path.write_text((before or "") + "\n# dirty\n")
                if kind == "staged":
                    self.git("add", "Cargo.toml")
                for task in ("version:cli", "release:version"):
                    result = self.task(task)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Working tree is dirty", result.stderr)
                if before is None:
                    path.unlink()
                else:
                    path.write_text(before)
                    self.git("add", "Cargo.toml")
        self.assertEqual(self.git("tag"), "")

    def test_website_revision_uses_numeric_max_and_today(self):
        prefix = "website@" + datetime.date.today().isoformat()
        result = self.task("release:version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(prefix + ".1", self.git("tag"))
        for tag in (prefix + ".9", prefix + ".10", prefix + ".999junk", "website@2000-01-01.999"):
            self.git("tag", tag)
        result = self.task("release:version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(prefix + ".11", self.git("tag"))
        self.assertEqual(self.git("log", "-1", "--format=%s"), "Initial")

    def test_release_tasks_push_branch_and_tags(self):
        remote = self.root / "remote.git"
        self.command("git", "init", "--bare", "-q", str(remote))
        self.git("remote", "add", "origin", str(remote))
        branch = self.git("branch", "--show-current")
        self.git("push", "-u", "origin", branch)
        for task, tag in (("release:cli", "cli@0.2.0"),
                          ("release:website", "website@" + datetime.date.today().isoformat() + ".1")):
            result = self.task(task)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("refs/tags/" + tag, self.git("ls-remote", "--tags", "origin"))
            self.assertIn(self.git("rev-parse", "HEAD"), self.git("ls-remote", "--heads", "origin", branch))


if __name__ == "__main__":
    unittest.main()
