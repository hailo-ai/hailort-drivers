"""Actual Make/shell removal tests with fixture-only DKMS state and mutations."""

import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAKE = shutil.which("make")
MODINFO = shutil.which("modinfo")
SUFFIXES = ("", ".gz", ".xz", ".zst")


class RemovalTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(0, os.geteuid(), "run fixture tests as a non-root user")
        temporary = ROOT / ".workbench/tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        self.fixture = tempfile.TemporaryDirectory(prefix="dkms regression-", dir=temporary)
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.state_path = self.root / "state.json"
        self.state = {"calls": [], "failures": {}, "partial": False,
                      "versions": {}, "installed": {}, "restore": {}}
        self.binary = self.root / "bin"
        self.binary.mkdir()
        backend = ROOT / "tests/dkms_lifecycle/fake_commands.py"
        for tool in ("id", "dkms", "modinfo", "rm", "depmod"):
            path = self.binary / tool
            path.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(backend)) + " " + tool + ' "$@"\n')
            path.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.binary) + os.pathsep + os.environ["PATH"],
                        HAILO_DKMS_FIXTURE=str(self.root), PYTHONDONTWRITEBYTECODE="1")
        self.kernel("kernel-a")
        self.kernel("kernel-b")

    def kernel(self, kernel):
        directory = self.root / "lib/modules" / kernel
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "modules.dep").write_text("pre-existing index: " + kernel)
        return directory

    def standalone(self, version="4.24.0", kernel="kernel-a", suffix=""):
        return self.module("kernel/drivers/misc", version, kernel, suffix)

    def module(self, directory, version, kernel, suffix):
        path = self.root / "lib/modules" / kernel / directory / ("hailo_pci.ko" + suffix)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("module bytes: " + version + "/" + kernel + suffix).encode())
        return path

    def register(self, version="4.24.0", kernel="kernel-a", suffix=""):
        path = self.module("updates/dkms", version, kernel, suffix)
        self.state["versions"].setdefault(version, {})[kernel] = "installed"
        self.state["installed"][version + "/" + kernel] = str(path)
        return path

    def call(self, argv, env=None):
        self.state_path.write_text(json.dumps(self.state))
        result = subprocess.run(argv, cwd=ROOT / "linux/pcie", env=env or self.env,
                                capture_output=True, text=True, timeout=30, check=False)
        self.state = json.loads(self.state_path.read_text())
        return result

    def make(self, target, kernel="kernel-a", version="4.24.0", dry_run=False):
        return self.call([MAKE, *(["-n"] if dry_run else []), target, "kernelver=" + kernel,
                          "DRIVER_VERSION=" + version, "INSTALL_MOD_PATH=" + str(self.root)])

    def helper(self, *arguments, env=None):
        return self.call(["/bin/sh", str(ROOT / "linux/pcie/dkms_uninstall.sh"), *arguments], env)

    def files(self):
        result = {}
        for path in self.root.rglob("*"):
            if path == self.state_path or path == self.binary or self.binary in path.parents:
                continue
            if path.is_symlink():
                content = "symlink:" + os.readlink(path)
                mode = None
            else:
                mode = stat.S_IMODE(path.stat().st_mode)
                if path.is_dir():
                    content = "directory"
                else:
                    try:
                        content = hashlib.sha256(path.read_bytes()).hexdigest()
                    except PermissionError:
                        content = "unreadable"
            result[str(path.relative_to(self.root))] = (mode, content)
        return result

    def assert_no_standalone_cleanup(self):
        self.assertFalse(any(call[0] in ("modinfo", "rm", "depmod") for call in self.state["calls"]))

    def assert_standalone_refused(self):
        before = self.files()
        self.state["calls"] = []
        result = self.make("uninstall_standalone")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("unsupported without installer ownership records", result.stderr)
        self.assertEqual(before, self.files())
        self.assertTrue(all(call[0] == "id" for call in self.state["calls"]))

    def test_uninstall_restores_older_and_same_version_originals(self):
        for original_version, suffix in ((v, s) for v in ("4.23.0", "4.24.0") for s in SUFFIXES):
            with self.subTest(original_version=original_version, suffix=suffix):
                self.register(suffix=".zst")
                other = self.register("4.23.0", "kernel-b", ".xz")
                original = self.standalone(original_version, suffix=suffix)
                expected = original.read_bytes()
                backup = self.root / "var/lib/dkms/hailo_pci/original_module/kernel-a/x86_64" / original.name
                backup.parent.mkdir(parents=True, exist_ok=True)
                original.rename(backup)
                collision = backup.parent / "collisions/keep.ko"
                collision.parent.mkdir(exist_ok=True)
                collision.write_bytes(b"pre-existing collision")
                self.state["restore"]["4.24.0/kernel-a"] = [str(backup), str(original)]
                result = self.make("uninstall")
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(expected, original.read_bytes())
                self.assertTrue(other.exists())
                self.assertEqual(b"pre-existing collision", collision.read_bytes())
                self.assert_no_standalone_cleanup()
                # Even an explicit subsequent standalone target may not infer
                # ownership from the restored original's matching version.
                self.assert_standalone_refused()

    def test_selected_kernel_and_version_leave_other_installations_unchanged(self):
        selected = self.register()
        other = self.register(kernel="kernel-b", suffix=".gz")
        self.state["versions"]["4.23.0"] = {"kernel-a": "built"}
        manual = self.standalone("4.22.0", suffix=".xz")
        before = {p: p.read_bytes() for p in (other, manual)}
        self.assertEqual(0, self.make("uninstall_dkms").returncode)
        self.assertFalse(selected.exists())
        for path, data in before.items():
            self.assertEqual(data, path.read_bytes())
        self.assertEqual({"kernel-a": "built"}, self.state["versions"]["4.23.0"])
        self.assertIn("kernel-b", self.state["versions"]["4.24.0"])
        self.assertIn(["dkms", "remove", "-m", "hailo_pci", "-v", "4.24.0", "-k", "kernel-a"], self.state["calls"])

    def test_all_kernels_target_is_still_version_scoped(self):
        self.register()
        self.register(kernel="kernel-b")
        self.state["versions"]["4.23.0"] = {"kernel-b": "built"}
        original = self.standalone("4.21.0", "kernel-b")
        self.assertEqual(0, self.make("uninstall_all_dkms").returncode)
        self.assertEqual({}, self.state["versions"]["4.24.0"])
        self.assertEqual({"kernel-b": "built"}, self.state["versions"]["4.23.0"])
        self.assertTrue(original.exists())
        self.assertIn(["dkms", "remove", "-m", "hailo_pci", "-v", "4.24.0", "--all"], self.state["calls"])
        self.assert_no_standalone_cleanup()

    def test_uninstall_defaults_to_running_kernel_only(self):
        running = subprocess.check_output(["uname", "-r"], text=True).strip()
        selected = self.register(kernel=running)
        other = self.register(kernel="kernel-b")
        result = self.call([MAKE, "uninstall", "DRIVER_VERSION=4.24.0"])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(selected.exists())
        self.assertTrue(other.exists())
        self.assertIn(["dkms", "remove", "-m", "hailo_pci", "-v", "4.24.0", "-k", running], self.state["calls"])
        self.assert_no_standalone_cleanup()

    def test_unregistered_removal_never_falls_back_to_standalone(self):
        self.standalone("4.23.0")
        before = self.files()
        self.assertNotEqual(0, self.make("uninstall").returncode)
        self.assertEqual(before, self.files())
        self.assert_no_standalone_cleanup()

    def test_dkms_failure_and_partial_failure_never_trigger_cleanup(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                self.register()
                other = self.register(kernel="kernel-b", suffix=".xz")
                original = self.standalone("4.23.0", suffix=".gz")
                data = original.read_bytes()
                self.state["failures"]["dkms-remove"] = 17
                self.state["partial"] = partial
                self.assertEqual(17, self.helper("4.24.0").returncode)
                self.assertEqual(data, original.read_bytes())
                self.assertTrue(other.exists())
                self.assert_no_standalone_cleanup()

    def test_partial_dkms_error_keeps_a_just_restored_same_version_original(self):
        self.register()
        other = self.register(kernel="kernel-b", suffix=".gz")
        original = self.standalone("4.24.0", suffix=".xz")
        data = original.read_bytes()
        backup = self.root / "original-module-backup.ko.xz"
        original.rename(backup)
        self.state["restore"]["4.24.0/kernel-a"] = [str(backup), str(original)]
        self.state["failures"]["dkms-remove"] = 17
        self.state["partial"] = True
        result = self.make("uninstall_all_dkms")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Error 17", result.stderr)
        self.assertEqual(data, original.read_bytes())
        self.assertTrue(other.exists())
        self.assert_no_standalone_cleanup()

    def test_repeated_removal_propagates_not_found_without_cleanup(self):
        self.register()
        self.standalone()
        self.assertEqual(0, self.helper("4.24.0", "--kernel", "kernel-a").returncode)
        before = self.files()
        self.assertEqual(3, self.helper("4.24.0", "--kernel", "kernel-a").returncode)
        self.assertEqual(before, self.files())
        self.assert_no_standalone_cleanup()

    def test_standalone_matching_version_without_dkms_is_not_owned(self):
        self.standalone()
        self.assertEqual({}, self.state["versions"])
        self.assert_standalone_refused()

    def test_standalone_different_or_unknown_version_is_preserved(self):
        self.standalone("4.23.0", suffix=".xz")
        self.standalone("unknown", suffix=".gz")
        self.assert_standalone_refused()

    def test_all_compression_suffixes_and_backup_files_are_preserved(self):
        for suffix in (*SUFFIXES, ".backup", ".unknown"):
            self.standalone(suffix=suffix)
        self.standalone(kernel="kernel-b", suffix=".gz")
        self.assert_standalone_refused()

    def test_malformed_and_empty_modules_are_preserved(self):
        self.standalone().write_bytes(b"not an ELF module")
        self.standalone(suffix=".xz").write_bytes(b"")
        self.assert_standalone_refused()

    def test_unreadable_module_is_preserved_without_inspection(self):
        path = self.standalone()
        original = path.read_bytes()
        path.chmod(0)
        with self.assertRaises(PermissionError):
            path.read_bytes()
        self.assert_standalone_refused()
        self.assertEqual(0, stat.S_IMODE(path.stat().st_mode))
        path.chmod(0o600)
        self.assertEqual(original, path.read_bytes())

    def test_symlink_module_and_symlink_directory_are_preserved(self):
        path = self.standalone()
        destination = path.with_name("original.ko")
        path.rename(destination)
        path.symlink_to(destination)
        self.assert_standalone_refused()
        directory = path.parent
        moved = directory.with_name("real-misc")
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        self.assert_standalone_refused()

    def test_non_regular_module_path_is_preserved(self):
        path = self.standalone()
        path.unlink()
        path.mkdir()
        self.assert_standalone_refused()
        self.assertTrue(path.is_dir())

    def test_absent_standalone_installation_still_reports_unsupported(self):
        self.assert_standalone_refused()

    def test_invalid_scope_never_reaches_dkms(self):
        for args in (("4.24.0", "--kernel", "../kernel-b"), ("4.24.0", "--kernel", "kernel-a\nother"),
                     ("4.24.0\nother",), ("4.24.0", "extra"), ("4.24.0", "--unknown", "kernel-a")):
            with self.subTest(args=args):
                self.assertEqual(2, self.helper(*args).returncode)
        self.assertEqual([], self.state["calls"])

    def test_missing_dkms_never_falls_back_to_filesystem_deletion(self):
        self.standalone()
        binary = self.root / "without-dkms"
        binary.mkdir()
        (binary / "grep").symlink_to(shutil.which("grep"))
        before = self.files()
        result = self.helper("4.24.0", "--kernel", "kernel-a", env=dict(self.env, PATH=str(binary)))
        self.assertEqual(1, result.returncode)
        self.assertEqual(before, self.files())
        self.assertEqual([], self.state["calls"])

    def test_install_has_no_forced_or_implicit_removal_and_targets_kernel(self):
        result = self.make("install_dkms", kernel="kernel-b", dry_run=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("--force", result.stdout)
        self.assertNotIn("dkms_uninstall.sh", result.stdout)
        self.assertNotIn("rm -", result.stdout)
        for action in ("build", "install"):
            self.assertIn(f'dkms {action} -m hailo_pci -v 4.24.0 -k "kernel-b"', result.stdout)

    def test_every_removal_target_checks_root_before_backend_mutation(self):
        self.standalone()
        self.register()
        self.state["uid"] = str(os.geteuid())
        before = self.files()
        for target in ("uninstall", "uninstall_dkms", "uninstall_all_dkms", "uninstall_standalone"):
            with self.subTest(target=target):
                result = self.make(target)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("should run as root", result.stderr)
        self.assertEqual(before, self.files())
        self.assertTrue(all(call[0] == "id" for call in self.state["calls"]))

    @unittest.skipUnless(os.environ.get("HAILO_REAL_TEST_MODULE") and MODINFO, "provide a GCC-built fixture module for real artifact checks")
    def test_real_matching_module_and_compressed_copies_are_not_owned(self):
        source = Path(os.environ["HAILO_REAL_TEST_MODULE"]).resolve()
        self.assertTrue(source.is_relative_to(ROOT / ".workbench/tmp"))
        data = source.read_bytes()
        version = subprocess.check_output([MODINFO, "-F", "version", str(source)], text=True).strip()
        kernel = subprocess.check_output([MODINFO, "-F", "vermagic", str(source)], text=True).split()[0]
        name = subprocess.check_output([MODINFO, "-F", "name", str(source)], text=True).strip()
        self.assertEqual("4.24.0", version)
        self.assertEqual("hailo_pci", name)
        self.kernel(kernel)
        for suffix in SUFFIXES:
            target = self.standalone(version, kernel, suffix)
            compressed = data
            if suffix == ".gz":
                compressed = gzip.compress(data, mtime=0)
            elif suffix == ".xz":
                compressed = lzma.compress(data)
            elif suffix == ".zst":
                compressed = subprocess.check_output(["zstd", "-q", "-c", str(source)])
            target.write_bytes(compressed)
        before = self.files()
        result = self.make("uninstall_standalone", kernel=kernel, version=version)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("unsupported without installer ownership records", result.stderr)
        self.assertEqual(before, self.files())
        self.assertTrue(all(call[0] == "id" for call in self.state["calls"]))


if __name__ == "__main__":
    unittest.main()
