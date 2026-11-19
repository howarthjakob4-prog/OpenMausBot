#!/usr/bin/env python3
"""Launcher icons for the OpenMausBot phone client — drawn in code (PIL):
a mouse-bot head (round ears, amber nose) in off-white on near-black."""
from PIL import Image, ImageDraw
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "android-src")
BG = (10, 10, 10)
FG = (242, 242, 242)
AMBER = (232, 163, 61)
GRAY = (140, 140, 140)

def draw_icon(px):
    S = px * 4  # supersample
    img = Image.new("RGB", (S, S), BG)
    d = ImageDraw.Draw(img)
    def C(cx, cy, r, fill):
        d.ellipse([ (cx-r)*S, (cy-r)*S, (cx+r)*S, (cy+r)*S ], fill=fill)
    def L(x1, y1, x2, y2, fill, w):
        d.line([x1*S, y1*S, x2*S, y2*S], fill=fill, width=max(1, int(w*S)))
    # ears
    C(0.29, 0.30, 0.135, FG); C(0.71, 0.30, 0.135, FG)
    C(0.29, 0.30, 0.062, BG); C(0.71, 0.30, 0.062, BG)
    # head
    C(0.50, 0.57, 0.265, FG)
    # eyes
    C(0.415, 0.53, 0.034, BG); C(0.585, 0.53, 0.034, BG)
    # nose
    C(0.50, 0.635, 0.030, AMBER)
    # whiskers
    for dy in (-0.035, 0.035):
        L(0.16, 0.60 + dy, 0.33, 0.615 + dy*0.4, GRAY, 0.012)
        L(0.84, 0.60 + dy, 0.67, 0.615 + dy*0.4, GRAY, 0.012)
    return img.resize((px, px), Image.LANCZOS)

for folder, px in [("mipmap-mdpi", 48), ("mipmap-hdpi", 72), ("mipmap-xhdpi", 96),
                   ("mipmap-xxhdpi", 144), ("mipmap-xxxhdpi", 192)]:
    out = os.path.join(BASE, "res", folder)
    os.makedirs(out, exist_ok=True)
    draw_icon(px).save(os.path.join(out, "ic_launcher.png"))
    print("wrote", out, px)
draw_icon(192).save(os.path.join(BASE, "assets", "www", "app-icon-192.png"))
print("wrote www app-icon-192.png")
