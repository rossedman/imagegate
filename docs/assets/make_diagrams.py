#!/usr/bin/env python3
"""Generate the README diagrams in the blueprint style of banner.svg.

    python3 docs/assets/make_diagrams.py   # writes docs/assets/diagram-*.svg
"""
from pathlib import Path

BG, LINE, DIM, TEXT, BRASS, DENY = "#0f1f31", "#c9d6e6", "#7f95ad", "#e6edf5", "#c9a15a", "#e59a7a"
MONO = 'font-family="IBM Plex Mono,JetBrains Mono,SFMono-Regular,Menlo,Consolas,monospace"'
SANS = 'font-family="Inter,Helvetica Neue,Helvetica,Arial,sans-serif"'
OUT = Path(__file__).resolve().parent


def frame(w, h, title, body):
    grid = "".join(
        f'<path d="M{x} 0V{h}" stroke="{LINE}" stroke-opacity="{.06 if x % 80 == 0 else .02}"/>' for x in range(0, w + 1, 16)
    ) + "".join(
        f'<path d="M0 {y}H{w}" stroke="{LINE}" stroke-opacity="{.06 if y % 80 == 0 else .02}"/>' for y in range(0, h + 1, 16)
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{title}">
<defs>
  <marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 1 L9 5 L0 9" fill="none" stroke="{LINE}" stroke-width="1.6"/></marker>
  <marker id="ab" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 1 L9 5 L0 9" fill="none" stroke="{BRASS}" stroke-width="1.6"/></marker>
  <marker id="ad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0 1 L9 5 L0 9" fill="none" stroke="{DENY}" stroke-width="1.6"/></marker>
</defs>
<rect width="{w}" height="{h}" fill="{BG}"/>{grid}
<rect x="12" y="12" width="{w-24}" height="{h-24}" fill="none" stroke="{LINE}" stroke-opacity=".3"/>
{body}
</svg>
'''


def label(x, y, s, color=DIM, size=12, anchor="start", weight=400):
    return f'<text x="{x}" y="{y}" {MONO} font-size="{size}" font-weight="{weight}" fill="{color}" text-anchor="{anchor}" letter-spacing=".4">{s}</text>'


def sequence():
    w, h = 1000, 540
    lanes = [("docker run", 130), ("dockerd", 380), ("imagegate", 630), ("registry", 870)]
    b = label(36, 44, "FIG. 1 · ONE CONTAINER CREATE", DIM, 11)
    for name, x in lanes:
        hi = name == "imagegate"
        b += f'<rect x="{x-70}" y="62" width="140" height="38" fill="{BG}" stroke="{BRASS if hi else LINE}" stroke-width="{1.6 if hi else 1.2}"/>'
        b += label(x, 86, name, TEXT, 14, "middle", 500)
        b += f'<path d="M{x} 100V{h-36}" stroke="{DIM}" stroke-dasharray="3 5"/>'
    X = dict(lanes)
    msgs = [
        ("docker run", "dockerd", "POST /containers/create", LINE, False),
        ("dockerd", "imagegate", "AuthZReq (every API call)", LINE, False),
        ("imagegate", "dockerd", "inspect image → digest", LINE, False),
        ("imagegate", "registry", "signatures + attestations", LINE, False),
        ("registry", "imagegate", "bundles · .sig · .att", DIM, True),
    ]
    y = 140
    for i, (f, t, text, col, dashed) in enumerate(msgs, 1):
        x1, x2 = X[f], X[t]
        d = ' stroke-dasharray="5 4"' if dashed else ""
        pad = 8 if x2 > x1 else -8
        b += f'<path d="M{x1+pad} {y}H{x2-pad}" stroke="{col}" stroke-width="1.4" marker-end="url(#a)"{d}/>'
        b += f'<circle cx="{x1+pad}" cy="{y}" r="9" fill="{BG}" stroke="{DIM}"/>' + label(x1 + pad, y + 4, str(i), DIM, 10, "middle")
        b += label((x1 + x2) / 2, y - 9, text, TEXT, 13, "middle")
        y += 48
    # verification note on the imagegate lane
    b += f'<rect x="{X["imagegate"]-118}" y="{y-14}" width="236" height="52" fill="{BG}" stroke="{BRASS}" stroke-width="1.2"/>'
    b += label(X["imagegate"], y + 6, "verify with sigstore-go", BRASS, 12.5, "middle")
    b += label(X["imagegate"], y + 26, "cache the verdict", BRASS, 12.5, "middle")
    y += 70
    for i, (f, t, text, col) in enumerate([("imagegate", "dockerd", "allow, or deny + reason", BRASS), ("dockerd", "docker run", "container, or the denial", LINE)], 6):
        x1, x2 = X[f], X[t]
        mk = "ab" if col == BRASS else "a"
        b += f'<path d="M{x1-8} {y}H{x2+8}" stroke="{col}" stroke-width="1.4" marker-end="url(#{mk})"/>'
        b += f'<circle cx="{x1-8}" cy="{y}" r="9" fill="{BG}" stroke="{DIM}"/>' + label(x1 - 8, y + 4, str(i), DIM, 10, "middle")
        b += label((x1 + x2) / 2, y - 9, text, col if col == BRASS else TEXT, 13, "middle")
        y += 48
    return frame(w, h, "Sequence of one container create through dockerd, imagegate and the registry", b)


def decision():
    w, h = 1000, 330
    b = label(36, 44, "FIG. 2 · THE DECISION, BY DIGEST", DIM, 11)
    steps = [
        ("image ref", "as written"),
        ("resolve digest", "via dockerd"),
        ("match rule", "first glob wins"),
        ("signature", "allowed identity?"),
        ("signed SBOM", "same digest?"),
        ("ALLOWED", "cached 24 h"),
    ]
    bw, gap, x0, y0 = 142, 20, 24, 92
    xs = [x0 + i * (bw + gap) for i in range(len(steps))]
    for i, ((t, sub), x) in enumerate(zip(steps, xs)):
        ok = t == "ALLOWED"
        b += f'<rect x="{x}" y="{y0}" width="{bw}" height="58" fill="{BG}" stroke="{BRASS if ok else LINE}" stroke-width="{1.6 if ok else 1.2}"/>'
        b += label(x + bw / 2, y0 + 25, t, BRASS if ok else TEXT, 14, "middle", 600 if ok else 500)
        b += label(x + bw / 2, y0 + 44, sub, BRASS if ok else DIM, 11, "middle")
        if i:
            col, mk = (BRASS, "ab") if ok else (LINE, "a")
            b += f'<path d="M{x-gap+3} {y0+29}H{x-3}" stroke="{col}" stroke-width="1.4" marker-end="url(#{mk})"/>'
    denies = [
        (1, "not in registry", "LOCAL_IMAGE"),
        (2, "no match", "NO_RULE"),
        (3, "none / wrong signer", "NO_SIGNATURE\nIDENTITY_MISMATCH"),
        (4, "none / unsigned", "NO_SBOM\nSBOM_UNTRUSTED"),
    ]
    for i, why, codes in denies:
        cx = xs[i] + bw / 2
        b += f'<path d="M{cx} {y0+58}V{y0+128}" stroke="{DENY}" stroke-width="1.2" stroke-dasharray="4 4" marker-end="url(#ad)"/>'
        b += label(cx + 8, y0 + 92, why, DIM, 11)
        lines = codes.split("\n")
        bh = 22 + 18 * len(lines)
        b += f'<rect x="{xs[i]+4}" y="{y0+132}" width="{bw-8}" height="{bh}" fill="{BG}" stroke="{DENY}" stroke-width="1.1"/>'
        for j, c in enumerate(lines):
            b += label(cx, y0 + 156 + 18 * j, c, DENY, 11.5, "middle", 500)
    return frame(w, h, "Decision flow: resolve the digest, match a rule, require a signature and a signed SBOM", b)


if __name__ == "__main__":
    (OUT / "diagram-sequence.svg").write_text(sequence())
    (OUT / "diagram-decision.svg").write_text(decision())
    print("wrote", OUT / "diagram-sequence.svg", OUT / "diagram-decision.svg")
