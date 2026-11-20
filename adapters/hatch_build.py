"""Bundle the repository's v0.1.0 schemas as acs/core/schemas when building from a checkout."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

SCHEMAS = Path(__file__).resolve().parent.parent / "specification" / "v0.1.0"


class SchemasBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        # A wheel built from the sdist finds the schemas the sdist already carries under src/.
        if version == "editable" or not SCHEMAS.is_dir():
            return
        dest = "src/acs/core/schemas" if self.target_name == "sdist" else "acs/core/schemas"
        build_data["force_include"][str(SCHEMAS)] = dest
