#!/usr/bin/env python3
"""Pin a draw.io SVG export to its own colors.

draw.io writes adaptive colors as CSS light-dark(<as drawn>, <inverted>), so a viewer in dark mode inverts the
diagram. This replaces each light-dark(a, b) with a and sets color-scheme to the given scheme, so the SVG looks
the same everywhere. Usage: svg_fixed_colors.py <file.svg> [dark|light]

Re-export the architecture diagram after editing docs/Ieso.drawio (from the repo root):
  /Applications/draw.io.app/Contents/MacOS/draw.io --export --format svg --border 16 \
    --output docs/Ieso-architecture.svg docs/Ieso.drawio
  scripts/svg_fixed_colors.py docs/Ieso-architecture.svg dark
"""
import sys

def first_arg_of_light_dark(s: str) -> str:
    out, i, key = [], 0, "light-dark("
    while True:
        j = s.find(key, i)
        if j < 0:
            out.append(s[i:])
            return "".join(out)
        out.append(s[i:j])
        k, depth, comma = j + len(key), 1, -1
        while depth:                      # scan to the matching ')' (bounded by the string length)
            c = s[k]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "," and depth == 1 and comma < 0:
                comma = k
            k += 1
        out.append(s[j + len(key):comma].strip())
        i = k

path, scheme = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "dark")
text = open(path, encoding="utf-8").read()
text = first_arg_of_light_dark(text).replace("color-scheme: light dark;", f"color-scheme: {scheme};") \
    .replace("color-scheme: light;", f"color-scheme: {scheme};")
open(path, "w", encoding="utf-8").write(text)
print(f"{path}: adaptive colors pinned, color-scheme {scheme}, light-dark left: {text.count('light-dark(')}")
