"""read_secret_file checks an owner-only secret through the descriptor it reads (issue #576, review R-M2).

The Guardian's ML-DSA-65 seed file goes through it. Checking a path and then opening it again lets the file change
in between, so the file is opened without following a symlink and the open descriptor is what gets checked.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from acs.client import SecretFilePermissionsError, read_secret_file
from acs.client import _secrets

SETTING = "ACS_GUARDIAN_SIGNING_KEY_FILE"


class ReadSecretFile(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = directory.name
        patcher = mock.patch.object(_secrets, "_IS_WINDOWS", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, mode: int, content: bytes = b"a" * 65, name: str = "secret.key") -> str:
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(content)
        os.chmod(path, mode)
        return path

    def test_an_owner_only_file_is_read(self) -> None:
        for mode in (0o600, 0o400):
            with self.subTest(mode=oct(mode)):
                path = self.write(mode, name=f"k{mode:o}")
                self.assertEqual(read_secret_file(path, setting=SETTING, max_bytes=100), b"a" * 65)

    def test_group_or_other_access_is_refused_under_the_setting_name(self) -> None:
        for mode in (0o640, 0o604, 0o644):
            with self.subTest(mode=oct(mode)), self.assertRaises(SecretFilePermissionsError) as caught:
                read_secret_file(self.write(mode, name=f"k{mode:o}"), setting=SETTING, max_bytes=100)
            self.assertTrue(str(caught.exception).startswith(f"{SETTING} "))
            self.assertIn("too permissive", str(caught.exception))

    def test_a_symlink_is_refused(self) -> None:
        link = os.path.join(self.dir, "link.key")
        os.symlink(self.write(0o600), link)
        with self.assertRaisesRegex(SecretFilePermissionsError, f"{SETTING} .*symlink"):
            read_secret_file(link, setting=SETTING, max_bytes=100)

    def test_a_directory_is_refused(self) -> None:
        with self.assertRaisesRegex(SecretFilePermissionsError, "regular file"):
            read_secret_file(self.dir, setting=SETTING, max_bytes=100)

    def test_the_descriptor_is_checked_not_the_path(self) -> None:
        # A path check that a later open could bypass would accept this: the path reports 0600, the file is 0644.
        path = self.write(0o644)
        owner_only = SimpleNamespace(st_mode=0o100600, st_uid=getattr(os, "geteuid", lambda: 0)())
        with mock.patch.object(_secrets.os, "stat", return_value=owner_only), \
                self.assertRaises(SecretFilePermissionsError):
            read_secret_file(path, setting=SETTING, max_bytes=100)

    def test_a_file_past_max_bytes_is_refused(self) -> None:
        with self.assertRaisesRegex(SecretFilePermissionsError, "larger than 64 bytes"):
            read_secret_file(self.write(0o600), setting=SETTING, max_bytes=64)

    def test_a_missing_file_raises_os_error(self) -> None:
        with self.assertRaises(OSError):
            read_secret_file(os.path.join(self.dir, "absent"), setting=SETTING, max_bytes=100)


if __name__ == "__main__":
    unittest.main()
