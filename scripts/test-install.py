"""Exercise archive installation in isolated homes; never touch system services."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().with_name("install.sh")


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home with spaces"
        self.home.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), XDG_DATA_HOME="relative",
                        XDG_CONFIG_HOME=str(self.home / ".config"),
                        XDG_STATE_HOME=str(self.home / ".local/state"),
                        XDG_BIN_HOME=str(self.home / ".local/bin"),
                        PATH=f"{self.tools}:/usr/bin:/bin")
        self.command("id", "echo 1000")
        self.command("uname", 'if [ "$1" = -s ]; then echo Linux; else echo x86_64; fi')
        self.command("fnox", "exit 0")
        self.source = self.root / "seccy"
        for directory in ("bin", "fnox", "system"):
            (self.source / directory).mkdir(parents=True)
        (self.source / "bin/seccy").write_text(
            '#!/bin/sh\nif [ "$1 $2" = "fnox info" ]; then echo "$HOME/plugin"; fi\n')
        (self.source / "bin/seccy-tpm").write_text("#!/bin/sh\nexit 0\n")
        for file in ("fnox/provider.lua", "system/seccy-tpm.conf", "system/seccy-tpm.service"):
            (self.source / file).write_text("fixture\n")
        self.archive = self.root / "seccy-cli@0.1.0-linux-x86_64.tar.gz"
        self.pack()

    def command(self, name, body):
        file = self.tools / name
        file.write_text("#!/bin/sh\n" + body + "\n")
        file.chmod(0o755)

    def pack(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.source, arcname="seccy")

    def run_install(self, *args):
        return subprocess.run(["bash", str(INSTALLER), "--install-only", *args],
                              env=self.env, capture_output=True, text=True)

    def test_install_and_upgrade_preserve_state_and_config(self):
        config = self.home / ".config/seccy/config.toml"
        config.parent.mkdir(parents=True)
        config.write_text("existing config")
        state = self.home / ".local/state/seccy/state.toml"
        state.parent.mkdir(parents=True)
        state.write_text("existing keys")
        for _ in range(2):
            result = self.run_install("--archive", str(self.archive))
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / ".local/bin/seccy").is_symlink())
        self.assertTrue((self.home / ".local/share/seccy/system/seccy-tpm.service").is_file())
        self.assertEqual(config.read_text(), "existing config")
        self.assertEqual(state.read_text(), "existing keys")

    def test_existing_command_is_preserved(self):
        command = self.home / ".local/bin/seccy"
        command.parent.mkdir(parents=True)
        command.write_text("other installation")
        result = self.run_install("--archive", str(self.archive))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(command.read_text(), "other installation")

    def test_piped_script_installs_without_a_terminal_in_install_only_mode(self):
        result = subprocess.run(
            ["bash", "-s", "--", "--install-only", "--archive", str(self.archive)],
            input=INSTALLER.read_text(), env=self.env, capture_output=True, text=True,
            start_new_session=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / ".local/bin/seccy").is_symlink())

    def test_piped_setup_without_terminal_reports_actionable_error(self):
        result = subprocess.run(
            ["bash", "-s", "--", "--archive", str(self.archive)],
            input=INSTALLER.read_text(), env=self.env, capture_output=True, text=True,
            start_new_session=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Setup requires a terminal", result.stderr)

    def test_existing_command_is_preserved_when_piped(self):
        command = self.home / ".local/bin/seccy"
        command.parent.mkdir(parents=True)
        command.write_text("other installation")
        result = subprocess.run(
            ["bash", "-s", "--", "--install-only", "--archive", str(self.archive)],
            input=INSTALLER.read_text(), env=self.env, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(command.read_text(), "other installation")

    def test_incomplete_archive_is_rejected(self):
        (self.source / "system/seccy-tpm.service").unlink()
        self.pack()
        result = self.run_install("--archive", str(self.archive))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Incomplete archive", result.stderr)
        self.assertFalse((self.home / ".local/bin/seccy").exists())

    def test_download_checksums_before_install(self):
        sums = self.root / "SHA256SUMS"
        self.env.update(FIXTURE_ARCHIVE=str(self.archive), FIXTURE_SUMS=str(sums))
        self.command("curl", '''
while [ "$#" -gt 0 ]; do
    case "$1" in
        *SHA256SUMS) source=$FIXTURE_SUMS ;;
        *.tar.gz) source=$FIXTURE_ARCHIVE ;;
        -o) shift; output=$1 ;;
    esac
    shift
done
cp "$source" "$output"
''')
        sums.write_text("0" * 64 + "  " + self.archive.name + "\n")
        result = self.run_install("--version", "cli@0.1.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse((self.home / ".local/bin/seccy").exists())
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        sums.write_text(digest + "  " + self.archive.name + "\n")
        result = self.run_install("--version", "cli@0.1.0")
        self.assertEqual(result.returncode, 0, result.stderr)

    def macos_fixture(self):
        # These stubs exercise installer layout/rollback, not Apple's validation.
        self.command("uname", 'if [ "$1" = -s ]; then echo Darwin; else echo arm64; fi')
        app = self.root / "fixture/Seccy.app"
        (app / "Contents/MacOS").mkdir(parents=True)
        (app / "Contents/Resources/fnox").mkdir(parents=True)
        executable = app / "Contents/MacOS/seccy"
        executable.write_text((self.source / "bin/seccy").read_text())
        executable.chmod(0o755)
        (app / "Contents/embedded.provisionprofile").write_text("profile")
        (app / "Contents/Resources/fnox/provider.lua").write_text("provider")
        self.env["FIXTURE_APP"] = str(app)
        self.command("ditto", '''
if [ "$1" = -x ]; then
    cp -R "$FIXTURE_APP" "$4/Seccy.app"
elif [ "${FAIL_COPY:-}" = 1 ]; then
    mkdir -p "$2"
    exit 1
else
    cp -R "$1" "$2"
fi
''')
        self.command("codesign", 'test "${FAIL_VERIFY:-}" != 1')
        self.command("xcrun", "exit 0")
        self.command("spctl", "exit 0")
        return app

    def test_macos_xdg_layout_and_complete_bundle_updates(self):
        app = self.macos_fixture()
        for value in (None, "", "relative", str(self.root / "custom data")):
            with self.subTest(xdg_data_home=value):
                if value is None:
                    self.env.pop("XDG_DATA_HOME", None)
                else:
                    self.env["XDG_DATA_HOME"] = value
                data = Path(value) if value and value.startswith("/") else self.home / ".local/share"
                destination = data / "seccy/Seccy.app"
                for revision in ("first", "updated"):
                    (app / "Contents/embedded.provisionprofile").write_text(revision)
                    result = self.run_install("--archive", str(self.archive))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((destination / "Contents/embedded.provisionprofile").read_text(), revision)
                    self.assertEqual((destination / "Contents/Resources/fnox/provider.lua").read_text(), "provider")
                    self.assertEqual((self.home / ".local/bin/seccy").resolve(), destination / "Contents/MacOS/seccy")
                self.assertFalse((self.home / "Applications").exists())

    def test_macos_failed_verification_or_copy_preserves_installed_bundle(self):
        self.macos_fixture()
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        destination = self.home / ".local/share/seccy/Seccy.app"
        marker = destination / "previous-installation"
        marker.write_text("preserve")
        for failure in ("FAIL_VERIFY", "FAIL_COPY"):
            with self.subTest(failure=failure):
                self.env[failure] = "1"
                result = self.run_install("--archive", str(self.archive))
                self.env.pop(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(marker.read_text(), "preserve")
                self.assertTrue((self.home / ".local/bin/seccy").is_file())


if __name__ == "__main__":
    unittest.main()
