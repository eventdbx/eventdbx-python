"""Cap'n Proto schemas bundled with the EventDBX client."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Iterator

__all__ = ["iter_schema_files"]


def iter_schema_files() -> Iterator[Path]:
    """Yield filesystem paths to bundled schemas.

    Useful for tooling that needs direct access to the raw schema files.
    """

    package_files = resources.files(__package__)
    for entry in package_files.iterdir():
        if entry.suffix == ".capnp":
            with resources.as_file(entry) as resolved:
                yield resolved
