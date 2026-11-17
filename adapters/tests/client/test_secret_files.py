"""read_trusted_file: the one reader for every secret or trusted file (issue #576, review rounds 2 and 3).

The HMAC secret, the Guardian's ML-DSA-65 seed, and the key document all go through it. It opens the file once,
without following a symlink and without blocking, then checks the open descriptor: a regular file, owned by this
user or root, in a directory no group or other can write unless it is sticky, and the caller's mode rule. It reads
at most max_bytes and raises the caller's error class for every problem.
"""
from __future__ import annotations

import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from acs.client import (
    SecretFilePermissionsError,
    SecretFileUnreadableError,
    load_hmac_secret,
    not_writable_by_others,
    owner_only,
    read_trusted_file,
)
from acs.client import _secrets

SETTING = "ACS_GUARDIAN_SIGNING_KEY_FILE"
POSIX = os.name != "nt"


class Refused(Exception):
    pass


class Unreadable(Exception):
    pass


def read(path: str, *, rule=owner_only, max_bytes: int = 100) -> bytes:
    return read_trusted_file(path, setting=SETTING, max_bytes=max_bytes, mode_rule=rule, refused=Refused,
                             unreadable=Unreadable)


@unittest.skipUnless(POSIX, "mode bits, owners, symlinks and FIFOs are POSIX")
class ReadTrustedFile(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = directory.name
        patcher = mock.patch.object(_secrets, "_IS_WINDOWS", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, mode: int, content: bytes = b"a" * 65, name: str = "secret.key", directory: str | None = None) -> str:
        path = os.path.join(directory or self.dir, name)
        with open(path, "wb") as f:
            f.write(content)
        os.chmod(path, mode)
        return path

    def test_an_owner_only_file_is_read(self) -> None:
        for mode in (0o600, 0o400):
            with self.subTest(mode=oct(mode)):
                self.assertEqual(read(self.write(mode, name=f"k{mode:o}")), b"a" * 65)

    def test_the_owner_only_rule_refuses_group_or_other_access(self) -> None:
        for mode in (0o640, 0o604, 0o644):
            with self.subTest(mode=oct(mode)), self.assertRaises(Refused) as caught:
                read(self.write(mode, name=f"k{mode:o}"))
            self.assertTrue(str(caught.exception).startswith(f"{SETTING} "))
            self.assertIn("too permissive", str(caught.exception))

    def test_the_public_rule_refuses_only_writes_by_others(self) -> None:
        self.assertEqual(read(self.write(0o644), rule=not_writable_by_others), b"a" * 65)
        for mode in (0o664, 0o646):
            with self.subTest(mode=oct(mode)), self.assertRaisesRegex(Refused, "writable by group or other"):
                read(self.write(mode, name=f"k{mode:o}"), rule=not_writable_by_others)

    def test_a_symlink_is_refused(self) -> None:
        link = os.path.join(self.dir, "link.key")
        os.symlink(self.write(0o600), link)
        with self.assertRaisesRegex(Refused, f"{SETTING} .*symlink"):
            read(link)

    def test_a_directory_is_refused(self) -> None:
        inner = os.path.join(self.dir, "inner")
        os.mkdir(inner, 0o700)
        with self.assertRaisesRegex(Refused, "regular file"):
            read(inner)

    def test_a_fifo_is_refused_without_blocking(self) -> None:
        # Review CR3-2: a plain open of a FIFO with no writer waits forever.
        fifo = os.path.join(self.dir, "fifo.key")
        os.mkfifo(fifo, 0o600)
        outcome: list[BaseException | bytes] = []

        def attempt() -> None:
            try:
                outcome.append(read(fifo))
            except BaseException as e:  # noqa: BLE001
                outcome.append(e)

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(5)
        if worker.is_alive():
            # Unblock the stuck open so the test process can exit, then fail.
            with open(fifo, "wb"):
                pass
            self.fail("opening a FIFO blocked")
        self.assertIsInstance(outcome[0], Refused)
        self.assertIn("regular file", str(outcome[0]))

    def test_the_open_flags(self) -> None:
        real_open = os.open
        flags_seen = []

        def spy(path, flags, *args):
            flags_seen.append(flags)
            return real_open(path, flags, *args)

        with mock.patch.object(_secrets.os, "open", side_effect=spy):
            read(self.write(0o600))
        for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
            if hasattr(os, name):
                self.assertTrue(flags_seen[0] & getattr(os, name), name)

    def _owned_by(self, uid: int) -> mock._patch:
        real_fstat = os.fstat

        def fstat(fd):
            st = real_fstat(fd)
            return SimpleNamespace(st_mode=st.st_mode, st_uid=uid, st_size=st.st_size)
        return mock.patch.object(_secrets.os, "fstat", side_effect=fstat)

    def test_another_owner_is_refused_and_root_is_accepted(self) -> None:
        path = self.write(0o600)
        with self._owned_by(os.geteuid() + 1), self.assertRaisesRegex(Refused, "owned by uid"):
            read(path)
        with self._owned_by(0):
            self.assertEqual(read(path), b"a" * 65)

    def test_a_parent_directory_others_can_write_is_refused_unless_sticky(self) -> None:
        # Review CR3-3: whoever can write the directory can replace the file between runs.
        shared = os.path.join(self.dir, "shared")
        os.mkdir(shared)
        path = self.write(0o600, directory=shared)
        for mode in (0o770, 0o707):
            os.chmod(shared, mode)
            with self.subTest(mode=oct(mode)), self.assertRaisesRegex(Refused, "directory .* writable"):
                read(path)
        os.chmod(shared, 0o1777)
        self.assertEqual(read(path), b"a" * 65)
        os.chmod(shared, 0o700)

    def test_an_os_error_after_open_raises_the_callers_class(self) -> None:
        # Review CR3-6: never a raw OSError.
        path = self.write(0o600)
        with mock.patch.object(_secrets.os, "fstat", side_effect=OSError(5, "I/O error")), \
                self.assertRaisesRegex(Unreadable, SETTING):
            read(path)
        with mock.patch.object(_secrets.os, "read", side_effect=OSError(5, "I/O error")), \
                self.assertRaisesRegex(Unreadable, SETTING):
            read(path)

    def test_a_missing_file_raises_the_callers_class(self) -> None:
        with self.assertRaisesRegex(Unreadable, SETTING):
            read(os.path.join(self.dir, "absent"))

    def test_unreadable_defaults_to_refused(self) -> None:
        with self.assertRaises(Refused):
            read_trusted_file(os.path.join(self.dir, "absent"), setting=SETTING, max_bytes=10, mode_rule=owner_only,
                              refused=Refused)

    def test_a_file_past_max_bytes_is_refused(self) -> None:
        with self.assertRaisesRegex(Refused, "larger than 64 bytes"):
            read(self.write(0o600), max_bytes=64)


@unittest.skipUnless(POSIX, "mode bits and FIFOs are POSIX")
class HmacSecretFile(unittest.TestCase):
    """load_hmac_secret reads through the same reader, so it never checks a path and opens it again (CR3-4)."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = directory.name
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        mock.patch.object(_secrets, "audit_event").start()
        self.addCleanup(mock.patch.stopall)

    def test_a_fifo_is_refused_without_blocking(self) -> None:
        fifo = os.path.join(self.dir, "hmac.key")
        os.mkfifo(fifo, 0o600)
        os.environ["ACS_HMAC_SECRET_FILE"] = fifo
        with self.assertRaisesRegex(SecretFilePermissionsError, "regular file"):
            load_hmac_secret()

    def test_an_empty_file_is_unreadable(self) -> None:
        path = os.path.join(self.dir, "hmac.key")
        with open(path, "wb"):
            pass
        os.chmod(path, 0o600)
        os.environ["ACS_HMAC_SECRET_FILE"] = path
        with self.assertRaisesRegex(SecretFileUnreadableError, "cannot be read"):
            load_hmac_secret()


class WindowsRule(unittest.TestCase):
    """Windows has no mode bits, so the owner-only rule refuses unless the operator opts in, and says so."""

    def setUp(self) -> None:
        patcher = mock.patch.object(_secrets, "_IS_WINDOWS", True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_refused_without_the_opt_in(self) -> None:
        with mock.patch.dict(os.environ, {_secrets._ALLOW_UNCHECKED_ENV: ""}):
            problem = owner_only(SETTING, "C:/key", 0o666)
        self.assertIn(_secrets._ALLOW_UNCHECKED_ENV, problem)

    def test_the_opt_in_warns_and_passes(self) -> None:
        with mock.patch.dict(os.environ, {_secrets._ALLOW_UNCHECKED_ENV: "1"}), \
                mock.patch("sys.stderr") as stderr:
            self.assertIsNone(owner_only(SETTING, "C:/key", 0o666))
        self.assertIn("was not checked", "".join(c.args[0] for c in stderr.write.call_args_list))

    def test_the_public_rule_checks_nothing_on_windows(self) -> None:
        self.assertIsNone(not_writable_by_others(SETTING, "C:/keys.json", 0o666))


if __name__ == "__main__":
    unittest.main()
