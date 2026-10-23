"""Vendor package holding bundled axe-core JavaScript engine."""

from pathlib import Path

AXE_JS_PATH = Path(__file__).resolve().parent / "axe.min.js"


def get_axe_script() -> str:
    """Return the bundled axe.min.js content."""
    if not AXE_JS_PATH.exists():
        raise FileNotFoundError(f"axe.min.js not found at {AXE_JS_PATH}")
    return AXE_JS_PATH.read_text(encoding="utf-8")
