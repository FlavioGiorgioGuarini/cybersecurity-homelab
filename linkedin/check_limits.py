#!/usr/bin/env python3
"""Validate LinkedIn character limits for every profile.*.md file.

LinkedIn limits (2026): headline 220, about 2600, experience title 100,
experience/project/education description 2000, company 100, skill name 80.
Counts are in Unicode code points, matching LinkedIn's counter.
"""
import re, sys, glob, pathlib

LIMITS = {"Headline": 220, "About": 2600, "title": 100, "description": 2000}
REQUIRED = ["Name", "Headline", "About", "Experience", "Education",
            "Licenses & Certifications", "Projects"]

def sections(text):
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith("## "):
            if cur: out[cur] = "\n".join(buf).strip()
            cur, buf = line[3:].strip(), []
        elif cur: buf.append(line)
    if cur: out[cur] = "\n".join(buf).strip()
    return out

def entries(block):
    for m in re.finditer(r"^### (.+?)\n(.*?)(?=^### |\Z)", block, re.S | re.M):
        title, body = m.group(1).strip(), m.group(2)
        d = body.split("- Description:", 1)
        desc = d[1].strip() if len(d) == 2 else body.strip()
        yield title, desc

ok = True
for path in sorted(glob.glob(str(pathlib.Path(__file__).parent / "profiles" / "profile.*.md"))):
    lang = path.split("profile.")[1].split(".md")[0]
    s = sections(pathlib.Path(path).read_text(encoding="utf-8"))
    rows = []
    for r in REQUIRED:
        if r not in s or not s[r]:
            rows.append(("MISSING", r, 0, 0)); ok = False
    for key in ("Headline", "About"):
        n = len(s.get(key, ""))
        rows.append(("OK" if n <= LIMITS[key] else "OVER", key, n, LIMITS[key]))
        ok &= n <= LIMITS[key]
    for sec in ("Experience", "Education", "Projects", "Licenses & Certifications"):
        for title, desc in entries(s.get(sec, "")):
            t, d = len(title), len(desc)
            rows.append(("OK" if t <= 100 else "OVER", f"{sec} title: {title[:40]}", t, 100))
            rows.append(("OK" if d <= 2000 else "OVER", f"{sec} desc:  {title[:40]}", d, 2000))
            ok &= t <= 100 and d <= 2000
    # factual anchors that every localisation must carry
    for anchor in ("80", "100", "148", "31", "FitActive", "VISIONOIR", "Universitas Mercatorum", "TryHackMe"):
        if anchor not in s.get("About", "") + s.get("Experience", "") + s.get("Education", ""):
            rows.append(("MISSING", f"anchor '{anchor}'", 0, 0)); ok = False
    print(f"\n=== {lang} ===")
    for st, name, n, lim in rows:
        flag = "" if st == "OK" else "  <-- " + st
        print(f"{st:7} {name:60} {n:5}/{lim}{flag}")
print("\nALL WITHIN LIMITS" if ok else "\nFAILURES FOUND"); sys.exit(0 if ok else 1)
