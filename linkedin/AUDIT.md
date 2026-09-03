# Final audit — LinkedIn profile redesign

Date: 2026-09-03 · Source of truth: `Flavio_Giorgio_Guarini_CV_Color.pdf` (2 pages, CV 2026) and the public `cybersecurity-homelab` repository.

## 1. What was requested vs. what was possible

| Requirement | Status | Notes |
|---|---|---|
| Analyse the CV in full before editing | Done | Both pages extracted and cross-checked against the repo (module count, endpoints, stack). |
| Access LinkedIn and edit the profile directly | **Blocked** | `www.linkedin.com`, `linkedin.com` and `api.linkedin.com` are all denied by the egress policy of this environment (proxy answers 403 on CONNECT). LinkedIn also exposes no third-party profile-writing API. No credentials were requested or used. |
| Redesign every section (headline, About, experience, results, education, certifications, skills, languages, projects, featured, URL) | Done as copy-ready content | `profiles/profile.*.md` + `shared-sections.md`. Each field respects LinkedIn's character limits (validated by `check_limits.py`). |
| Photo and banner | Banner done, photo guidance only | `assets/linkedin-banner-1584x396.png` at native size, with the profile-photo overlay zone kept clear. A profile photo cannot be produced without inventing a likeness, so precise shooting guidance is given instead. |
| Integrate the FitActive commercial result (€80K–€100K, hundreds of memberships) | Done | Supported by the CV ("Vendita di centinaia di abbonamenti … stimato in €80K – €100K"). Kept as an *estimated* range in every language, in both About and the Experience entry. |
| Multilingual versions: IT, EN, ES, FR, DE, NL, RU, ZH | Done | Eight files. LinkedIn supports all eight as secondary-profile languages (Chinese as Simplified). Each is a localisation, not a literal translation; the checker confirms every factual anchor survived. |
| Optimise for international business / sales / marketing / creative / tech / graduate roles | Done | Headline and About lead with cyber keywords, then surface sales results, leadership, creative work and languages; Open-to-work titles cover all five tracks. |
| Verify before destructive changes, verify after each change | Partially | Cannot compare against the live profile. The README instructs a side-by-side check before overwriting each existing entry; every file was verified for limits and factual anchors after every edit. |
| Do not invent | Done | Every number, date, employer, title and skill traces to the CV or the repo. Two deliberate framings: the reception role at "Fitness Bari Japigia S.r.l." is presented as "FitActive · Fitness Bari Japigia S.r.l." (the brand you named plus the legal entity on the CV); the confidential 2024 role keeps the CV's wording and adds an explicit "details withheld" line. |

## 2. Changes made, section by section

- **Headline** — from a job title to a keyword-dense positioning line: role, four SOC keywords, the TryHackMe Top 3% proof, the hybrid human/communication angle, languages and availability. 215–220 characters in each alphabetic language; shorter in Chinese, which is denser.
- **About** — restructured into thesis, credentials, five "what I bring" axes (technical, engineering, human intelligence, commercial/operational results, leadership), languages, mobility, links. Under the 2,600 cap in every language.
- **Experience** — six entries, most recent first, each with employment type, location and 2–4 achievement bullets. FitActive carries the quantified sales result; the confidential role is framed for credibility without disclosure; VISIONOIR's closure is stated as a strategic choice, as on the CV; the freelance sound-design role is dated Nov 2019 – present as on the CV.
- **Education** — two parallel bachelor's degrees at Universitas Mercatorum with expected 2027 completion and accelerated track, plus the US high-school diploma with its activities (keynote 400+, Prom King, Eco-Council, 80 volunteer hours).
- **Certifications** — Advent of Cyber 2025 with a curriculum summary; the credential URL is left for you to paste. The in-progress Python for Security training is placed under *Courses* because the CV names no issuing organisation.
- **Projects** — CSF SIEM 3D v2.0 with the stack verified in the repo (FastAPI, PostgreSQL, SQLAlchemy, 15+ endpoints, 8 modules, Three.js, Docker).
- **Honors** — TryHackMe Top 3% (rank 54,086, level 0xA, 148 rooms, 31 badges) and the 2019 bronze medal.
- **Skills** — 50 skills grouped by axis, five pinned. **Languages** — five with LinkedIn proficiency levels. **Featured** — portfolio, repo, TryHackMe, certificate. **URL** — `linkedin.com/in/flaviogiorgioguarini`. **Open to work** — titles, locations and types listed.

## 3. LinkedIn constraints to keep in mind when applying
- Secondary-language profiles localise only Name, Headline, About, Experience and Education. Skills, Languages, Certifications, Projects, Featured and Honors are shared and shown once, so they are in English.
- Headline 220, About 2,600, entry titles 100, descriptions 2,000, skills max 100, Featured items are ordered manually.
- LinkedIn counts characters as Unicode code points; the checker uses the same rule, so Chinese and Russian counts match LinkedIn's counter.
- The public URL must be unique; two fallbacks are listed.

## 4. Verification performed
- `check_limits.py`: all eight files within limits and carrying every factual anchor (80/100 figures, 148, 31, FitActive, VISIONOIR, Universitas Mercatorum, TryHackMe).
- Each localisation read in full for register, terminology and consistency with the English master.
- Banner rendered at exactly 1584×396 px and checked for the photo-overlay zone.
- Links: the GitHub repository answered 200 from this environment; the portfolio and TryHackMe hosts are outside the egress policy and were not reachable here, so confirm both open publicly before pinning them.

## 5. Left for you (cannot be done from here)
1. Apply the content on LinkedIn following `README.md` (about 45 minutes).
2. Paste the Advent of Cyber certificate URL into the certification entry and the Featured item.
3. Upload a profile photo that follows the guidance.
4. Ask FitActive for a short recommendation referencing the sales result; a third-party recommendation is the strongest credibility signal LinkedIn offers for a quantified claim.
