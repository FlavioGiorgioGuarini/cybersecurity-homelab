# LinkedIn profile redesign — Flavio Giorgio Guarini

Complete, copy-ready content for the LinkedIn profile, derived only from the 2026 CV and the public `cybersecurity-homelab` repository. Nothing here is invented: every number, date, employer and skill traces back to the CV.

## Why this lives in the repo instead of on LinkedIn already
LinkedIn (`www.linkedin.com`, `api.linkedin.com`) is denied by the egress policy of the environment this work ran in (HTTP 403 on CONNECT), and LinkedIn offers no profile-writing API to third parties. The profile therefore has to be applied by hand, which takes about 45 minutes with the files below. See `AUDIT.md` for the full list of limitations.

## Contents
| Path | What it is |
|---|---|
| `profiles/profile.en.md` | English master. Recommended primary language. |
| `profiles/profile.it.md` | Italian. |
| `profiles/profile.es.md` | Spanish (neutral international). |
| `profiles/profile.fr.md` | French. |
| `profiles/profile.de.md` | German (DACH conventions). |
| `profiles/profile.nl.md` | Dutch. |
| `profiles/profile.ru.md` | Russian. |
| `profiles/profile.zh.md` | Simplified Chinese. |
| `shared-sections.md` | Skills, languages, featured, URL, contact, open-to-work, photo and banner guidance. These sections are language-independent on LinkedIn. |
| `assets/linkedin-banner-1584x396.png` | Banner at LinkedIn's native size. `assets/banner.html` is its source. |
| `check_limits.py` | Validates every profile file against LinkedIn's character limits and checks that every factual anchor survived localisation. |
| `build_page.py` | Builds `linkedin-profile-kit.html`, a tabbed page with a copy button on every field. |
| `AUDIT.md` | Final audit: what changed, what was verified, what could not be done. |

## How to apply (order matters)
1. **Custom URL and contact** — `Me → View profile → Edit public profile & URL`. Set the URL from `shared-sections.md`, then update contact info.
2. **Photo and banner** — upload `assets/linkedin-banner-1584x396.png` as the background photo. Follow the photo guidance in `shared-sections.md`.
3. **Primary profile (English)** — open `profiles/profile.en.md`. Paste Headline, About, then each Experience, Education, Certification, Project and Honor entry in the order given. Before overwriting an existing entry, compare it with the new one so nothing you value is lost.
4. **Skills and languages** — from `shared-sections.md`. Add skills in the listed order and pin the first five as Top Skills. LinkedIn caps skills at 100.
5. **Featured** — `Add profile section → Recommended → Add featured`. Pin the four links in the given order.
6. **Secondary languages** — on your profile, `Add profile in another language` (top right of the intro card). LinkedIn supports Italian, Spanish, French, German, Dutch, Russian and Chinese (Simplified). For each, paste Name, Headline, About, then every Experience and Education entry from the matching file. Skills, certifications, projects and languages are shared automatically; the Projects and Certifications sections in each file exist only so a visitor in that language can still read the wording if you ever choose to add it in the shared description.
7. **Open to work** — `Open to → Finding a new job`, recruiters only, with the titles and locations in `shared-sections.md`.
8. **Verify** — view the profile logged out (`View as → Public`) and switch the page language to check each secondary version renders.

## Re-validating after edits
```bash
python3 linkedin/check_limits.py      # limits and factual anchors
python3 linkedin/build_page.py        # rebuild the copy-ready page
```
