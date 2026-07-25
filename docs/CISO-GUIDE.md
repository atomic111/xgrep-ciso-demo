# Presenting xgrep to a CISO — a 15-minute walkthrough

This is a script for demoing xgrep against the intentionally-vulnerable Acme
DevOps Toolkit in this repo. It moves from *"what did it find"* to *"how do I
know it's real"* to *"where does my team see it"* — the three questions a
security leader actually asks.

The pitch in one sentence: **xgrep reports issues that are real and exploitable,
proves them by following the data, and puts them where your team already
works — GitHub and Mondoo — with an executive view on top.**

---

## 0. Why this matters (30 seconds)

Most SAST tools fail not because they miss bugs but because they cry wolf. Once
a scanner floods a team with maybe-bugs, people stop reading its output and real
issues slip through. xgrep optimizes for **accuracy**: when it reports a
vulnerability, it should be real and exploitable. This demo is built to show
both the catches *and* the restraint (it stays quiet on the safe code right next
to the vulnerable code).

## 1. The HTML dashboard (the executive view)

Open the **GitHub Pages dashboard** (Settings → Pages URL after the first run,
or the `security-report` workflow's job summary). Talk to:

- The **posture verdict** band — "Action required", with the count of critical
  and high issues that are exploitable.
- The four **severity KPIs** and the three **lenses**: application code,
  leaked secrets, vulnerable dependencies. One number each — this is the "how
  bad is it" slide.
- **Top exploitable risks** — each card names the file and line, the CWE/OWASP
  category, and the concrete remediation. This is what goes into a ticket.

> The dashboard is generated from the scan's JSON by
> [`report/gen_report.py`](../report/gen_report.py) and rebuilt on every push —
> no manual reporting.

## 2. A real bug, proven by data-flow (the credibility moment)

Run the scan live:

```bash
xgrep scan . --rules rules --with-builtin security,secrets
```

Pick the **command injection** in `app/backup.py`. Show the chain:

```
POST /backup  →  archive_name = request.form["name"]   # untrusted SOURCE
              →  create_archive(name)
              →  _run_tar(name)
              →  subprocess.check_output("tar … " + name, shell=True)  # SINK
```

The point: xgrep didn't flag `subprocess` because it looks scary. It flagged it
because it **followed attacker-controlled input across three function calls**
into a shell. That's the difference between "technically imperfect" and
"exploitable."

Then show the **restraint**: `app/directory.py` has a vulnerable query *and* a
safe parameterized one (`find_user_safe`). Only the vulnerable one is flagged.
Same for [`app/safe_ops.py`](../app/safe_ops.py) — correct code, zero findings.

## 3. Secrets your grep won't find

```bash
xgrep scan . --decode      # finds a secret hidden inside a base64 blob (assets/telemetry.b64)
xgrep scan . --history     # finds a token that was deleted from deploy/deploy.sh but lives in git history
```

The story: attackers scrape git history and decode blobs. A secret you "removed"
in a later commit is still a live credential. xgrep checks the places a simple
text search misses — and suppresses obvious placeholders (`CHANGE_ME`, the AWS
example key) so the signal stays clean.

## 4. The whole dependency tree (SCA)

```bash
xgrep scan . --mondoo-config /path/to/mondoo.json
```

~77 CVE / End-of-Life advisories from `poetry.lock`, checked against Mondoo's
vulnerability database — the same scan, no separate tool. Point out that code
findings and dependency findings render together and land on the same asset.

## 5. Your own policy, encoded

Open [`rules/acme-http-wrapper.xgrep.yaml`](../rules/acme-http-wrapper.xgrep.yaml).
It enforces an *organization* rule — "all outbound HTTP must go through the
vetted `acme_http` client" — that no built-in rule could know. This is how a
security team turns a written policy into an automated gate.

## 6. Where the team sees it — CI

- **GitHub Security tab**: SARIF upload means every finding is a code-scanning
  alert with data-flow, tags, and stable de-duplication. On a pull request the
  scan is **diff-aware** — reviewers see only what the change introduced.
- **Mondoo Platform**: every scan reports code + secrets + CVEs to space
  `bold-rubin-524886`, attached to this repo as one asset, tracked over time.
  This is where posture across *all* repos rolls up.

Show `.github/workflows/xgrep.yml` — the whole scan is a handful of lines, and
Mondoo reporting is just one environment secret.

## 7. Close: AI triage and fixes

In Claude Code (skills are installed under `.claude/`, MCP server in `.mcp.json`):

- *"Triage the xgrep findings"* → the `xgrep-triage` skill walks the code graph
  and classifies each finding, so a human reviews verdicts, not raw output.
  ([example](triage-example.md))
- *"Fix the confirmed true positives"* → `xgrep-fix` applies fixes through a
  verify/apply harness and **re-scans to prove each fix**.

The arc: xgrep finds the exploitable issue, proves it, files it where the team
works, and an agent can propose the fix — with the scanner as the check that the
fix actually worked.

---

### One-line commands for the live demo

```bash
xgrep scan . --rules rules --with-builtin security,secrets   # code + secrets, exploitable
xgrep scan . --decode                                        # encoded secret
xgrep scan . --history                                       # secret in git history
xgrep scan . --mondoo-config mondoo.json                     # + dependency CVEs, + report to Mondoo
```
