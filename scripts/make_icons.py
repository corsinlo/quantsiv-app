"""Regenerate the served logo and favicon PNGs from assets/logo-symbol.png (WP9, A47).

Run with any Python that has Pillow (it is not an app dependency):
    python -m venv /tmp/pil && /tmp/pil/bin/pip install pillow
    /tmp/pil/bin/python scripts/make_icons.py

The logo kit (kept outside this repo) asks for a simplified favicon drawn at 16 and 32 px; until
one exists, these are downscaled from the full symbol.
"""

from pathlib import Path

from PIL import Image

SOURCE = Path("assets/logo-symbol.png")
OUT = Path("app/static")
SIZES = {
    "logo-64.png": 64,
    "logo-128.png": 128,
    "favicon-32.png": 32,
    "favicon-16.png": 16,
    "apple-touch-icon.png": 180,
}

with Image.open(SOURCE) as source:
    image = source.convert("RGBA")
    for name, size in SIZES.items():
        resized = image.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(OUT / name, optimize=True)
        print(f"{name}: {(OUT / name).stat().st_size} bytes")
