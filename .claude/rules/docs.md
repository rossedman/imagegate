---
paths:
  - "docs/**"
  - "mkdocs.yml"
  - "README.md"
---

# Documentation rules

- The site is MkDocs Material (`mkdocs.yml`, pages in `docs/`, theme
  overrides in `docs/overrides/`, styles in `docs/stylesheets/extra.css`).
  `make docs` runs `mkdocs build --strict`; it must pass.
- Diagrams are Mermaid fences so they render both on GitHub and on the site.
- `docs/runbook.md` anchors (`#no_sbom`, lowercase) are linked from denial messages
  via `defaults.helpURL`. Keep one `###` heading per reason code.
- Document behaviour as it is, with exact flag names, paths and reason
  codes. If code and docs disagree, fix the docs in the same change.
- Plain, short sentences. Specific numbers and commands over adjectives.
