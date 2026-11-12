"""Exercise archive installation in isolated homes; never touch system services."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().with_name("install.sh")


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "home with spaces"
        self.home.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), XDG_DATA_HOME="relative",
                        XDG_CONFIG_HOME=str(self.home / ".config"),
                        XDG_STATE_HOME=str(self.home / ".local/state"),
                        XDG_BIN_HOME=str(self.home / ".local/bin"),
                        PATH=f"{self.tools}:/usr/bin:/bin")
        if not shutil.which("sha256sum", path="/usr/bin:/bin"):
            self.command("sha256sum", 'exec shasum -a 256 "$@"')
        self.command("id", "echo 1000")
        self.command("uname", 'if [ "$1" = -s ]; then echo Linux; else echo x86_64; fi')
        self.command("fnox", 'test "$1 $2 $3 $4" = "plugin link --force seccy"')
        self.source = self.root / "seccy"
        for directory in ("bin", "fnox", "system"):
            (self.source / directory).mkdir(parents=True)
        (self.source / "bin/seccy").write_text(
            '#!/bin/sh\ncase "$1 $2" in\n"--version " ) echo "seccy 0.1.0" ;;\n"fnox info") echo "$HOME/plugin" ;;\n"fnox init") ;;\n*) exit 99 ;;\nesac\n')
        (self.source / "bin/seccy-tpm").write_text("#!/bin/sh\nexit 0\n")
        for file in ("fnox/provider.lua", "system/seccy-tpm.conf", "system/seccy-tpm.service"):
            (self.source / file).write_text("fixture\n")
        (self.source / "bin/seccy").chmod(0o755)
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
        return subprocess.run(["bash", str(INSTALLER), *args],
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

    def test_same_version_skips_and_new_version_updates(self):
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        binary = self.home / ".local/share/seccy/bin/seccy"
        before = binary.stat().st_mtime_ns
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already installed", result.stdout)
        self.assertEqual(binary.stat().st_mtime_ns, before)
        # A matching explicit release must not even download the archive.
        self.command("curl", "exit 99")
        result = self.run_install("--version", "cli@0.1.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already installed", result.stdout)
        source = self.source / "bin/seccy"
        source.write_text(source.read_text().replace("0.1.0", "0.2.0"))
        self.pack()
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0.2.0", binary.read_text())

    def test_existing_command_is_replaced(self):
        command = self.home / ".local/bin/seccy"
        command.parent.mkdir(parents=True)
        command.write_text("other installation")
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(command.is_symlink())

    def test_piped_script_installs_without_a_terminal(self):
        result = subprocess.run(
            ["bash", "-s", "--", "--archive", str(self.archive)],
            input=INSTALLER.read_text(), env=self.env, capture_output=True, text=True,
            start_new_session=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / ".local/bin/seccy").is_symlink())

    def test_piped_install_needs_no_terminal_or_setup(self):
        result = subprocess.run(
            ["bash", "-s", "--", "--archive", str(self.archive)],
            input=INSTALLER.read_text(), env=self.env, capture_output=True, text=True,
            start_new_session=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.home / ".config").exists())
        self.assertFalse((self.home / ".local/state").exists())

    def test_existing_command_is_replaced_when_piped(self):
        command = self.home / ".local/bin/seccy"
        command.parent.mkdir(parents=True)
        command.write_text("other installation")
        result = subprocess.run(
            ["bash", "-s", "--", "--archive", str(self.archive)],
            input=INSTALLER.read_text(), env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(command.is_symlink())

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
                for version, revision in (("0.1.0", "first"), ("0.2.0", "updated")):
                    executable = app / "Contents/MacOS/seccy"
                    executable.write_text((self.source / "bin/seccy").read_text().replace("0.1.0", version))
                    (app / "Contents/embedded.provisionprofile").write_text(revision)
                    result = self.run_install("--archive", str(self.archive))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((destination / "Contents/embedded.provisionprofile").read_text(), revision)
                    self.assertEqual((destination / "Contents/Resources/fnox/provider.lua").read_text(), "provider")
                    self.assertEqual((self.home / ".local/bin/seccy").resolve(), destination / "Contents/MacOS/seccy")
                self.assertFalse((self.home / "Applications").exists())

    def test_macos_failed_verification_or_copy_preserves_installed_bundle(self):
        app = self.macos_fixture()
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        destination = self.home / ".local/share/seccy/Seccy.app"
        marker = destination / "previous-installation"
        marker.write_text("preserve")
        executable = app / "Contents/MacOS/seccy"
        executable.write_text(executable.read_text().replace("0.1.0", "0.2.0"))
        for failure in ("FAIL_VERIFY", "FAIL_COPY"):
            with self.subTest(failure=failure):
                self.env[failure] = "1"
                result = self.run_install("--archive", str(self.archive))
                self.env.pop(failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(marker.read_text(), "preserve")
                self.assertTrue((self.home / ".local/bin/seccy").is_file())

    def macos_service_fixture(self):
        app = self.macos_fixture()
        executable = app / "Contents/MacOS/seccy"
        executable.write_text(executable.read_text().replace(
            '"fnox init") ;;',
            '''"service install")
    printf '%s\\n' "$0" >> "$HOME/service-calls"
    "$0" --version >> "$HOME/service-calls"
    test "${FAIL_SERVICE:-}" != 1 ;;
"fnox init") ;;'''))
        plist = self.home / "Library/LaunchAgents/fyi.seccy.agent.plist"
        plist.parent.mkdir(parents=True)
        plist.write_text("existing service definition")
        return executable

    def test_macos_updates_refresh_existing_service_from_permanent_bundle(self):
        source = self.macos_service_fixture()
        template = source.read_text()
        calls = self.home / "service-calls"
        installed = self.home / ".local/share/seccy/Seccy.app/Contents/MacOS/seccy"
        for version in ("0.1.0", "0.2.0", "0.3.0"):
            with self.subTest(version=version):
                source.write_text(template.replace("0.1.0", version))
                result = self.run_install("--archive", str(self.archive))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls.read_text().splitlines()[-2:],
                                 [str(installed), f"seccy {version}"])
        self.assertEqual(len(calls.read_text().splitlines()), 6)

    def test_macos_same_version_repairs_service_without_replacing_bundle(self):
        self.macos_service_fixture()
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = self.home / ".local/share/seccy/Seccy.app/Contents/MacOS/seccy"
        before = installed.stat().st_mtime_ns
        self.command("curl", "exit 99")
        for args in (("--archive", str(self.archive)), ("--version", "cli@0.1.0")):
            result = self.run_install(*args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("already installed", result.stdout)
            self.assertEqual(installed.stat().st_mtime_ns, before)
        self.assertEqual(len((self.home / "service-calls").read_text().splitlines()), 6)

    def test_macos_service_failure_is_reported_and_can_be_retried(self):
        self.macos_service_fixture()
        self.env["FAIL_SERVICE"] = "1"
        for _ in range(2):
            result = self.run_install("--archive", str(self.archive))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refreshing its service failed", result.stderr)
        self.env.pop("FAIL_SERVICE")
        result = self.run_install("--archive", str(self.archive))
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
