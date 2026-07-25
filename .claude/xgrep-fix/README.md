# xgrep Fix

A Claude Code skill for fixing a **whole set** of xgrep findings in one pass,
driven by a scan `findings.json` — optionally one that `xgrep-triage` has reviewed.

## What it does

- Takes a scan `findings.json` as input — optionally triaged (findings carry
  `extra.triage`) — not a single finding
- **Fixes only triage-confirmed true-positives** with `xgrep fix --confirmed`;
  findings reviewed `false-positive` are skipped automatically
- **Auto-applies** every `deterministic` fix through the harness in one batch
- **Drives the assisted loop** for each `assisted` finding (author a byte-span
  edit, verify it, iterate on the rejection reason, apply it)
- **Surfaces advisory** guidance (e.g. rotate a leaked secret) as hand-fix items
- Reports a consolidated, per-fingerprint summary; never reports a fix without a
  green re-scan

## How it relates to the other skills

`xgrep-triage` decides *which* findings are real and writes its verdict back into the
`findings.json` (`extra.triage`). **`xgrep-fix`** then remediates the set — fixing
only the confirmed true-positives with `--confirmed`, or every in-scope finding when
the file isn't triaged. It is the **batch** layer: per-finding it uses the same
verify/apply mechanics as `xgrep-remediate`, which stays the single-finding primitive.

| Skill | Scope |
|-------|-------|
| `xgrep-triage` | Decide whether findings are real; write `extra.triage` back |
| `xgrep-remediate` | Fix **one** confirmed finding |
| **`xgrep-fix`** | Fix **a set** of findings / triage-confirmed true positives |

## Usage

```
# Fix everything fixable in a scan (un-triaged)
/xgrep-fix findings.json

# Fix only the triage-confirmed true positives (findings carry extra.triage)
/xgrep-fix findings.json   # the skill uses `xgrep fix --confirmed`

# Custom rule pack (propagated to every scan/verify/apply)
/xgrep-fix findings.json --rules security-rules/
```

## Installation

```bash
xgrep skill install xgrep-fix
# or
claude skill install ./skills/xgrep-fix
```

## Prerequisites

- `xgrep` CLI must be installed and available in PATH
- Target files must be writable for `fix apply`

## The harness

Every edit — deterministic or agent-authored — passes the same gates before it is
written:

1. **Parse-clean** — the patched file must still parse.
2. **Re-scan** — the targeted finding must clear, with no new equal-or-higher
   finding in the region touched.
3. **Atomic write** — a temp file is renamed over the target; no partial-write
   window.

The same operations are available over MCP as `fix_verify` / `fix_apply`.
