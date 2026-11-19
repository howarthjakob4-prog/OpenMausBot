#!/usr/bin/env python3
"""Launcher icons for the MausBot phone client — Jakob's own Ferrum dragon
shield, hand-composited in PIL from his real logo (no generated art, no
mouse). The shield is centered on black at 94% so launcher masks never
clip the gold ring."""
from PIL import Image
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "android-src")
LOGO = os.path.expanduser("~/workspace/user/ferrum-dragon-shield-logo.jpg")
BLACK = (0, 0, 0)

def make_icon(px):
    S = px * 4  # supersample
    img = Image.new("RGB", (S, S), BLACK)
    logo = Image.open(LOGO).convert("RGB")
    side = int(S * 0.94)
    logo = logo.resize((side, side), Image.LANCZOS)
    off = (S - side) // 2
    img.paste(logo, (off, off))
    return img.resize((px, px), Image.LANCZOS)

for folder, px in [("mipmap-mdpi", 48), ("mipmap-hdpi", 72), ("mipmap-xhdpi", 96),
                   ("mipmap-xxhdpi", 144), ("mipmap-xxxhdpi", 192)]:
    out = os.path.join(BASE, "res", folder)
    os.makedirs(out, exist_ok=True)
    make_icon(px).save(os.path.join(out, "ic_launcher.png"))
    print("wrote", out, px)
make_icon(192).save(os.path.join(BASE, "assets", "www", "app-icon-192.png"))
print("wrote www app-icon-192.png")
