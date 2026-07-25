# Acme DevOps Toolkit — an xgrep capability demo

> ⚠️ **This repository is intentionally vulnerable.** It is a demonstration
> harness for [**xgrep**](https://github.com/mondoohq/xgrep), Mondoo's
> Semgrep-compatible SAST scanner. The `app/` service contains deliberately
> insecure code and fake credentials so the scanner has something to find.
> **Do not deploy it, and do not reuse any of its code.**

This repo shows a security leader everything xgrep does, end to end:

- **Finds real, exploitable bugs** in application code — proven by data-flow
  (taint) analysis, not just pattern-matching.
- **Catches leaked secrets** — in plaintext, hidden one encoding layer deep, and
  even after they were deleted from the current code but remain in git history.
- **Flags vulnerable dependencies** (CVEs + End-of-Life packages) from the
  lockfile, via Mondoo's vulnerability database.
- **Enforces your own policy** with a custom rule.
- **Runs in CI** on every push and pull request, uploading results to the GitHub
  **Security tab** and to **Mondoo Platform**.
- **Produces a CISO-facing dashboard** published to GitHub Pages.
- **Drives AI triage and fixes** with the bundled Claude Code skills + MCP server.

## What a CISO sees

| Where | What |
|-------|------|
| 📊 **[GitHub Pages dashboard](docs/CISO-GUIDE.md#1-the-html-dashboard)** | Executive HTML report — posture verdict, severity KPIs, top exploitable risks with remediation, secrets, and a CVE table. Rebuilt on every push. |
| 🔐 **GitHub Security tab** | Every finding as a code-scanning alert, with data-flow, CWE/OWASP tags, and stable de-duplication across scans. |
| ☁️ **Mondoo Platform** | All findings (code, secrets, dependency CVEs) attached to this repo as a single asset in space `bold-rubin-524886`, tracked over time alongside the rest of your posture. |

See the **[CISO presentation guide](docs/CISO-GUIDE.md)** for a scripted 15-minute walkthrough.

## The vulnerabilities (and why they fire)

Each feature module puts an HTTP entry point (the untrusted **source**) and a
dangerous operation (the **sink**) in the same file, connected through helper
functions — so xgrep proves the bug by following the data across the calls.

| Finding | Severity | Where | Capability shown |
|---------|----------|-------|------------------|
| OS command injection | Critical | [`app/backup.py`](app/backup.py) | Interprocedural taint → shell |
| SQL injection | Critical | [`app/directory.py`](app/directory.py) | Taint into a query (safe query nearby is *not* flagged) |
| Insecure deserialization (pickle) | Critical | [`app/plugins.py`](app/plugins.py) | RCE sink |
| Code injection (`eval`) | Critical | [`app/plugins.py`](app/plugins.py) | Taint into `eval` |
| JWT algorithm confusion | Critical | [`app/auth.py`](app/auth.py) | Auth bypass pattern |
| SSRF | High | [`app/proxy.py`](app/proxy.py) | Taint into outbound request |
| Disabled TLS verification | High | [`app/proxy.py`](app/proxy.py) | MITM exposure |
| Path traversal | High | [`app/reports.py`](app/reports.py) | Taint into a filesystem path |
| Reflected XSS | High | `app/directory.py`, `app/proxy.py` | Taint into the HTTP response |
| Weak password hashing (MD5) | Medium | [`app/auth.py`](app/auth.py) | Crypto misuse |
| Direct `requests` usage | Medium | [`app/proxy.py`](app/proxy.py) | **Custom Acme policy rule** |
| Debug mode enabled | Low | [`app/server.py`](app/server.py) | Hardening |
| Leaked secrets (GitHub/Slack/Stripe) | Medium | [`config/app.env`](config/app.env) | Secret detection |
| Leaked secret (base64-encoded AWS key) | Medium | `assets/telemetry.b64` | `--decode` — one encoding layer deep |
| Leaked secret in git history (DigitalOcean) | Medium | `deploy/deploy.sh` | `--history` — deleted-but-not-gone |
| ~77 dependency CVEs / EOL | mixed | [`poetry.lock`](poetry.lock) | Software Composition Analysis |

`app/services`-style safe equivalents live in [`app/safe_ops.py`](app/safe_ops.py) — xgrep stays quiet on them, which is the point: precision, not noise.

## Run it yourself

```bash
npm install -g @mondoohq/xgrep      # or: brew install xgrep

# 1. Application code + secrets, exploitable-only
xgrep scan . --rules rules --with-builtin security,secrets

# 2. Add encoded-secret detection
xgrep scan . --rules rules --with-builtin security,secrets --decode

# 3. Secrets that were committed and later deleted (walks git history)
xgrep scan . --history

# 4. Dependency CVEs + EOL (needs a Mondoo service account; see below)
xgrep scan . --mondoo-config /path/to/mondoo.json
```

### Reporting to Mondoo Platform

Reporting is **automatic** whenever a Mondoo service account is present — there
is no flag to turn it on. In CI it is supplied as one secret,
`MONDOO_CONFIG_BASE64` (a base64-encoded `mondoo.yml`). Findings attach to this
repo as an asset in your space. Pass `--incognito` for a local-only scan.

## CI

Two GitHub Actions workflows run on every push to `main` and every pull request:

- [`.github/workflows/xgrep.yml`](.github/workflows/xgrep.yml) — scans (diff-aware
  on PRs), uploads **SARIF** to GitHub Code Scanning, and reports to Mondoo.
- [`.github/workflows/report.yml`](.github/workflows/report.yml) — builds the
  **CISO HTML dashboard** and deploys it to GitHub Pages.

## AI triage & fix (fully wired)

The bundled Claude Code skills are installed under [`.claude/`](.claude) and the
xgrep MCP server is configured in [`.mcp.json`](.mcp.json). Open this repo in
Claude Code and ask:

- *"Triage the xgrep findings in this repo"* → `xgrep-triage` walks the code
  graph and classifies each finding true/false positive. See a sample in
  [`docs/triage-example.md`](docs/triage-example.md).
- *"Fix the confirmed findings"* → `xgrep-fix` applies fixes through the
  verify/apply harness and re-scans to prove each one.

## Layout

```
app/            intentionally-vulnerable Flask service (one concern per module)
rules/          custom Acme policy rule
config/         leaky .env (plaintext secrets)
assets/         base64-encoded secret (for --decode)
deploy/         deploy script whose secret lives only in git history (for --history)
poetry.lock     old, vulnerable dependency pins (drives the SCA scan)
report/         gen_report.py — turns xgrep JSON into the CISO HTML dashboard
.github/        the two CI workflows
.claude/        bundled xgrep AI skills
docs/           CISO presentation guide + example AI triage report
```
