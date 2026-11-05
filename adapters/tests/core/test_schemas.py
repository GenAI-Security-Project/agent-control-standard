from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from acs.core import _schemas
from acs.core import schemas_dir


def _schema_tree(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "request-envelope.json").write_text("{}")
    return root


class SchemasDir(unittest.TestCase):
    def test_override_wins_even_when_it_does_not_exist(self) -> None:
        self.assertEqual(schemas_dir("/no/such/dir"), Path("/no/such/dir"))

    def test_bundled_copy_wins_over_the_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundled = _schema_tree(Path(tmp) / "bundled")
            checkout = _schema_tree(Path(tmp) / "checkout")
            with mock.patch.object(_schemas, "_BUNDLED", bundled), \
                 mock.patch.object(_schemas, "_CHECKOUT", checkout):
                self.assertEqual(schemas_dir(), bundled)

    def test_checkout_is_used_when_nothing_is_bundled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = _schema_tree(Path(tmp) / "checkout")
            with mock.patch.object(_schemas, "_BUNDLED", Path(tmp) / "absent"), \
                 mock.patch.object(_schemas, "_CHECKOUT", checkout):
                self.assertEqual(schemas_dir(), checkout)

    def test_missing_schemas_raise_instead_of_returning_a_bad_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(_schemas, "_BUNDLED", Path(tmp) / "a"), \
                 mock.patch.object(_schemas, "_CHECKOUT", Path(tmp) / "b"):
                with self.assertRaises(FileNotFoundError):
                    schemas_dir()

    def test_source_checkout_resolves_to_the_repository_schemas(self) -> None:
        repo = Path(__file__).resolve().parents[3] / "specification" / "v0.1.0"
        self.assertEqual(schemas_dir().resolve(), repo.resolve())


if __name__ == "__main__":
    unittest.main()
