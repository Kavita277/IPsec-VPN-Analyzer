"""Vercel Serverless Function entry point for FastAPI."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so that ai, assessment, analyzer,
# and backend packages can all be imported cleanly in Vercel's runtime.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import app  # noqa: E402
