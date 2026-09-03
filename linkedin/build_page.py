#!/usr/bin/env python3
"""Build linkedin-profile-kit.html: every profile language in tabs, one copy button per field."""
import re, json, pathlib, html

ROOT = pathlib.Path(__file__).parent
LANGS = [("en","English","Primary"),("it","Italiano",""),("es","Español",""),("fr","Français",""),
         ("de","Deutsch",""),("nl","Nederlands",""),("ru","Русский",""),("zh","中文",""),]

def parse(text):
    secs, cur, buf = [], None, []
    for line in text.splitlines():
        if line.startswith("## "):
            if cur: secs.append((cur, "\n".join(buf).strip()))
            cur, buf = line[3:].strip(), []
        elif cur: buf.append(line)
    if cur: secs.append((cur, "\n".join(buf).strip()))
    out = []
    for name, body in secs:
        if "### " not in body:
            out.append({"name": name, "entries": [{"title": None, "fields": [], "desc": body}]}); continue
        entries = []
        for m in re.finditer(r"^### (.+?)\n(.*?)(?=^### |\Z)", body, re.S | re.M):
            title, rest = m.group(1).strip(), m.group(2)
            fields = re.findall(r"^- ([A-Za-z &]+): (.*)$", rest, re.M)
            fields = [(k, v) for k, v in fields if k != "Description"]
            d = rest.split("- Description:", 1)
            desc = d[1].strip() if len(d) == 2 else ""
            entries.append({"title": title, "fields": fields, "desc": desc})
        out.append({"name": name, "entries": entries})
    return out

data = {}
for code, label, tag in LANGS:
    p = ROOT / "profiles" / f"profile.{code}.md"
    if p.exists(): data[code] = parse(p.read_text(encoding="utf-8"))
shared = (ROOT / "shared-sections.md").read_text(encoding="utf-8")

def block(text, key):
    n = len(text)
    lim = {"Headline": 220, "About": 2600}.get(key, 2000)
    return (f'<div class="field"><div class="fhead"><span class="flabel">{html.escape(key)}</span>'
            f'<span class="count">{n}<span class="lim">/{lim}</span></span>'
            f'<button class="copy" type="button">Copy</button></div>'
            f'<pre class="val">{html.escape(text)}</pre></div>')

panels = []
for code, label, tag in LANGS:
    if code not in data: continue
    parts = [f'<section class="panel" data-lang="{code}" {"" if code=="en" else "hidden"}>']
    for sec in data[code]:
        parts.append(f'<h2>{html.escape(sec["name"])}</h2>')
        for e in sec["entries"]:
            if e["title"] is None:
                parts.append(block(e["desc"], sec["name"])); continue
            parts.append('<article class="entry">')
            parts.append(block(e["title"], "Title"))
            for k, v in e["fields"]:
                parts.append(f'<div class="meta"><span class="mk">{html.escape(k)}</span><span class="mv">{html.escape(v)}</span></div>')
            if e["desc"]: parts.append(block(e["desc"], "Description"))
            parts.append('</article>')
    parts.append('</section>')
    panels.append("\n".join(parts))

tabs = "".join(f'<button class="tab{" on" if c=="en" else ""}" data-lang="{c}" type="button">{l}'
               f'{"<em>"+t+"</em>" if t else ""}</button>' for c, l, t in LANGS if c in data)

page = f'''<title>Guarini LinkedIn Kit</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sora:wght@300;600;700&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
:root{{--bg:#F7F8FB;--ink:#111827;--mute:#5B6478;--line:#D9DEE8;--card:#FFFFFF;--acc:#0F3F7A;--acc2:#12A58A;--tabbg:#EDF0F6;--sel:#DCE9FF}}
@media (prefers-color-scheme: dark){{:root:not([data-theme="light"]){{--bg:#0B1220;--ink:#E6ECF7;--mute:#9AA8C2;--line:#233252;--card:#111B2E;--acc:#8FBBFF;--acc2:#5EE7C4;--tabbg:#141F35;--sel:#1B2E52}}}}
:root[data-theme="dark"]{{--bg:#0B1220;--ink:#E6ECF7;--mute:#9AA8C2;--line:#233252;--card:#111B2E;--acc:#8FBBFF;--acc2:#5EE7C4;--tabbg:#141F35;--sel:#1B2E52}}
body{{background:var(--bg);color:var(--ink);font-family:"Source Serif 4",Georgia,serif;font-size:16px;line-height:1.55;margin:0}}
.wrap{{max-width:980px;margin:0 auto;padding:40px 24px 80px}}
header h1{{font-family:Sora,system-ui,sans-serif;font-weight:700;font-size:34px;letter-spacing:-.01em;margin:0;text-wrap:balance}}
header p{{color:var(--mute);margin:8px 0 0;max-width:65ch}}
.note{{border-left:3px solid var(--acc2);padding:10px 16px;margin:24px 0;background:var(--card);color:var(--mute);font-size:15px}}
.tabs{{display:flex;flex-wrap:wrap;gap:6px;margin:28px 0 20px;position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:2}}
.tab{{font-family:Sora,system-ui,sans-serif;font-size:14px;font-weight:600;border:1px solid var(--line);background:var(--tabbg);color:var(--ink);padding:8px 14px;border-radius:6px;cursor:pointer}}
.tab em{{font-style:normal;font-family:"IBM Plex Mono",monospace;font-size:11px;letter-spacing:.08em;color:var(--acc2);margin-left:8px}}
.tab.on{{background:var(--sel);border-color:var(--acc)}}
.tab:focus-visible,.copy:focus-visible{{outline:2px solid var(--acc2);outline-offset:2px}}
h2{{font-family:Sora,system-ui,sans-serif;font-size:14px;letter-spacing:.14em;text-transform:uppercase;color:var(--mute);margin:40px 0 12px;font-weight:600}}
.entry{{border-top:1px solid var(--line);padding-top:12px;margin-top:16px}}
.field{{margin:10px 0}}
.fhead{{display:flex;align-items:center;gap:12px;font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--mute)}}
.flabel{{letter-spacing:.08em;text-transform:uppercase}}
.count{{margin-left:auto;font-variant-numeric:tabular-nums}} .lim{{opacity:.6}}
.copy{{font-family:Sora,system-ui,sans-serif;font-size:12px;font-weight:600;border:1px solid var(--line);background:var(--card);color:var(--acc);padding:4px 10px;border-radius:4px;cursor:pointer}}
.copy.done{{color:var(--acc2);border-color:var(--acc2)}}
.val{{white-space:pre-wrap;word-wrap:break-word;font:inherit;background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px 14px;margin:6px 0 0;max-width:72ch}}
.meta{{display:flex;gap:10px;font-size:14px;margin:2px 0}} .mk{{color:var(--mute);min-width:130px;font-family:"IBM Plex Mono",monospace;font-size:12px;padding-top:3px}}
.shared{{white-space:pre-wrap;background:var(--card);border:1px solid var(--line);border-radius:4px;padding:16px;font-family:"IBM Plex Mono",monospace;font-size:13px;line-height:1.5;overflow-x:auto}}
@media (prefers-reduced-motion: no-preference){{.copy{{transition:color .15s}}}}
</style>
<div class="wrap">
<header><h1>LinkedIn profile kit — Flavio Giorgio Guarini</h1>
<p>Every field of the redesigned profile in eight languages, with live character counts against LinkedIn's limits. Pick a language, copy a field, paste it into LinkedIn.</p></header>
<div class="note">LinkedIn could not be reached from the environment that produced this kit, so the profile is applied by hand. Order and instructions are in <code>linkedin/README.md</code>; secondary languages localise only Name, Headline, About, Experience and Education.</div>
<nav class="tabs" aria-label="Language">{tabs}<button class="tab" data-lang="shared" type="button">Shared sections</button></nav>
{"".join(panels)}
<section class="panel" data-lang="shared" hidden><h2>Shared across all languages</h2><div class="shared">{html.escape(shared)}</div></section>
</div>
<script>
document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click',()=>{{
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===t));
  document.querySelectorAll('.panel').forEach(p=>p.hidden=p.dataset.lang!==t.dataset.lang);
  try{{localStorage.setItem('lk-lang',t.dataset.lang)}}catch(e){{}}
}}));
try{{const s=localStorage.getItem('lk-lang');const b=s&&document.querySelector('.tab[data-lang="'+s+'"]');if(b)b.click()}}catch(e){{}}
document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',async()=>{{
  const txt=b.closest('.field').querySelector('.val').textContent;
  try{{await navigator.clipboard.writeText(txt);b.textContent='Copied';b.classList.add('done');setTimeout(()=>{{b.textContent='Copy';b.classList.remove('done')}},1500)}}
  catch(e){{b.textContent='Select text';}}
}}));
</script>'''
out = ROOT / "linkedin-profile-kit.html"
out.write_text(page, encoding="utf-8")
print(f"wrote {out} ({len(page)} chars, languages: {', '.join(data)})")
