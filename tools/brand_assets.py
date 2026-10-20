#!/usr/bin/env python3
"""Regenerates the vector brand assets in frontend/public/ (Logo B, the ledger shield).

    python tools/brand_assets.py --font /path/to/Inter-SemiBold.ttf

Writes mark.svg, favicon.svg (the simplified 16 px variant), logo.svg (mark + wordmark)
and manifest.webmanifest. Needs `pip install fonttools` and Inter SemiBold (SIL OFL;
https://github.com/rsms/inter). The wordmark is converted to plain path outlines here, so
no SVG depends on a font at display time. Colours follow the browser's light/dark setting
through a prefers-color-scheme rule inside each file. The raster files (PNG, ICO) are made
from these by tools/brand_rasters.mjs. Not part of the app or its tests; output is committed.
"""

import argparse
import json
from pathlib import Path

PUBLIC = Path(__file__).resolve().parent.parent / "frontend" / "public"
WORDMARK = "OPA Compliance Wizard"

# Light and dark colours from the Logo B board.
STYLE = ("<style>.s{stroke:#1E293B}.t{stroke:#B45309}.f{fill:#1E293B}.w{fill:#1E293B}"
         "@media (prefers-color-scheme:dark){.s{stroke:#E2E8F0}.t{stroke:#F59E0B}.f{fill:#E2E8F0}.w{fill:#F4F4F5}}</style>")
FAV_STYLE = ("<style>.f{fill:#1E293B}.t{stroke:#F59E0B}"
             "@media (prefers-color-scheme:dark){.f{fill:#E2E8F0}.t{stroke:#B45309}}</style>")

MARK_PATHS = (
    '<path class="s" d="M16 2.5 27 6.5V15c0 7.2-4.6 12-11 14.5C9.6 27 5 22.2 5 15V6.5Z" fill="none" stroke-width="2.4" stroke-linejoin="round"/>'
    '<path class="s" d="M11 11h10M11 15.5h10" fill="none" stroke-width="2.4" stroke-linecap="round"/>'
    '<path class="t" d="m11.5 20.5 3 3 6-6.5" fill="none" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>'
)
FAV_PATHS = (
    '<path class="f" d="M16 2 28 6.5V15c0 7.5-5 12.5-12 15C9 27.5 4 22.5 4 15V6.5Z"/>'
    '<path class="t" d="m10.5 16.5 4 4 7.5-8.5" fill="none" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>'
)


def wordmark_path(font_path, text, size):
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.pens.transformPen import TransformPen
    from fontTools.ttLib import TTFont

    font = TTFont(font_path)
    glyphs, cmap = font.getGlyphSet(), font.getBestCmap()
    scale = size / font["head"].unitsPerEm
    x, parts = 0.0, []
    for ch in text:
        name = cmap[ord(ch)]
        pen = SVGPathPen(glyphs, ntos=lambda v: f"{v:.2f}".rstrip("0").rstrip("."))
        glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, 0)))  # flip y; baseline at 0
        if pen.getCommands():
            parts.append(pen.getCommands())
        x += glyphs[name].width * scale
    return " ".join(parts), x


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--font", required=True, help="Inter SemiBold .ttf")
    args = ap.parse_args()
    PUBLIC.mkdir(parents=True, exist_ok=True)
    head = '<svg xmlns="http://www.w3.org/2000/svg" '
    (PUBLIC / "mark.svg").write_text(
        head + f'viewBox="0 0 32 32" role="img" aria-label="OPA Compliance Wizard mark">{STYLE}{MARK_PATHS}</svg>\n', encoding="utf-8")
    (PUBLIC / "favicon.svg").write_text(
        head + f'viewBox="0 0 32 32" role="img" aria-label="OPA Compliance Wizard">{FAV_STYLE}{FAV_PATHS}</svg>\n', encoding="utf-8")
    d, width = wordmark_path(args.font, WORDMARK, 22)
    total = 44 + width
    (PUBLIC / "logo.svg").write_text(
        head + f'viewBox="0 0 {total:.0f} 40" width="{total:.0f}" height="40" role="img" aria-label="OPA Compliance Wizard">{STYLE}'
        f'<g transform="translate(0 4) scale(1.0)">{MARK_PATHS}</g>'
        f'<path class="w" transform="translate(44 27)" d="{d}"/></svg>\n', encoding="utf-8")
    (PUBLIC / "manifest.webmanifest").write_text(json.dumps({
        "name": "OPA Compliance Wizard", "short_name": "OPA Wizard", "description": "Evidence for OPA audits",
        "start_url": "/", "display": "standalone", "background_color": "#1E293B", "theme_color": "#1E293B",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
            {"src": "/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
        ]}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {PUBLIC}/ (wordmark {width:.0f} px wide)")


if __name__ == "__main__":
    main()
