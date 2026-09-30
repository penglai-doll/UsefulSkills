"""Verify write blocking before mounting and refuse unverified success."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_linux_loader_contract import load_script


class ReadonlyMountTests(unittest.TestCase):
    def test_whole_image_needs_a_recognized_filesystem(self):
        module = load_script("mount_evidence.py")
        result = {"format": {"kind": "raw-style"}, "evidence_file": {"path": "/evidence/disk.img"}}
        privilege = {"can_run_privileged": True, "prefix": []}
        commands, mounts = module.plan_mounts(result, "/mnt/case", privilege)
        self.assertTrue(commands[0]["blocked"])
        self.assertIsNone(mounts[0]["readonly"])
        self.assertNotIn("manual_command", commands[0])
        result["filesystem_probe"] = {"type": "ext4"}
        commands, mounts = module.plan_mounts(result, "/mnt/case", privilege)
        self.assertFalse(commands[0]["blocked"])
        self.assertIn("noload", mounts[0]["options"])
        self.assertIsNone(mounts[0]["success"])

    def _exercise(self, device_ro="1", mount_ro="ro", mount_rc=0):
        module = load_script("mount_evidence.py")
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            target = str(Path(tmp) / "mount")
            command = {"stage": "mount-read-only", "command": [
                "mount", "-t", "ext4", "-o", "ro,noload,loop,offset=4096,sizelimit=8192", "image.img", target]}
            mount = {"mount_path": target, "success": None, "readonly": None}

            def run(args, timeout=60):
                calls.append(args)
                stdout, rc = "", 0
                if args[0] == "losetup" and "--find" in args:
                    stdout = "/dev/loop7\n"
                elif args[0] == "blockdev":
                    stdout = device_ro
                elif args[0] == "mount":
                    rc = mount_rc
                elif args[0] == "findmnt":
                    stdout = json.dumps({"filesystems": [{"source": "/dev/loop7", "target": target,
                                                           "fstype": "ext4", "options": mount_ro}]})
                return {"args": args, "returncode": rc, "stdout": stdout, "stderr": ""}

            with patch.object(module.shutil, "which", side_effect=lambda name: name), patch.object(module, "run_command", side_effect=run):
                module.execute_plan([command], [mount])
        return command, mount, calls

    def test_block_device_is_verified_before_mount(self):
        command, mount, calls = self._exercise()
        self.assertTrue(mount["success"])
        self.assertTrue(mount["readonly"])
        self.assertEqual([args[0] for args in calls], ["losetup", "blockdev", "mount", "findmnt"])
        self.assertIn("--read-only", calls[0])
        self.assertIn("--offset", calls[0])
        self.assertIn("--sizelimit", calls[0])
        self.assertEqual(command["executed_command"][-2], "/dev/loop7")
        self.assertIn("ro,noload", command["executed_command"])
        self.assertEqual(mount["cleanup_commands"][-1], ["losetup", "-d", "/dev/loop7"])

    def test_writable_device_is_never_mounted(self):
        _, mount, calls = self._exercise(device_ro="0")
        self.assertFalse(mount["success"])
        self.assertFalse(any(args[0] == "mount" for args in calls))
        self.assertEqual(calls[-1], ["losetup", "-d", "/dev/loop7"])

    def test_successful_command_with_writable_mount_is_rejected_and_cleaned(self):
        _, mount, calls = self._exercise(mount_ro="rw")
        self.assertFalse(mount["success"])
        self.assertFalse(mount["readonly"])
        self.assertEqual([args[0] for args in calls[-2:]], ["umount", "losetup"])

    def test_mount_failure_detaches_loop(self):
        _, mount, calls = self._exercise(mount_rc=1)
        self.assertFalse(mount["success"])
        self.assertFalse(any(args[0] == "findmnt" for args in calls))
        self.assertEqual(calls[-1], ["losetup", "-d", "/dev/loop7"])


if __name__ == "__main__":
    unittest.main()
