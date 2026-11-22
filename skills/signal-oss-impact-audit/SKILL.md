---
name: signal-oss-impact-audit
description: Audit public Signal Homelab adoption and maintainer activity using verifiable GitHub links, unique external contributors, and independently evidenced downstream use.
---

# Audit open-source impact

Verify the repository owner, default branch, license and observation date from the source. Mark unpublished or inaccessible information as unknown. State the measurement window in UTC when reporting time-bounded counts.

- For issues and PRs, use official GitHub result pages or equivalent API responses. Filter by repository and requested dates. Keep open issues, closed issues, authored PRs and merged PRs distinct. Deduplicate contributor accounts and identify which are outside the owning team before counting external contributions.
- Treat stars, forks, views and clones as separate signals. Attribute a downstream use only to public proof such as a dependency declaration, link, reproducible integration, or supplied adopter statement that can be cited. Keep traffic metrics aggregate and use the source’s documented window when available.
- Record one evidence row per claim with metric, count or unknown, period, retrieval date and source link. Separate observed use from planned outreach and compare only equivalent periods.
- For program eligibility, read current official terms and compare each relevant criterion with the evidence. Report unsupported criteria as unverified. Keep activity organic and the audit read-only.

[GitHub issue and PR search](https://docs.github.com/en/search-github/searching-on-github/searching-issues-and-pull-requests) · [GitHub repository traffic](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-traffic-to-a-repository)
