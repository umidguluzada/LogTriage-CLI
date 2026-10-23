"""Shared pytest fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from parsers import TimeNormalizer  # noqa: E402


@pytest.fixture(scope="session")
def config() -> dict[str, Any]:
    with open(ROOT / "config.json", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture()
def normalizer() -> TimeNormalizer:
    return TimeNormalizer("UTC")
