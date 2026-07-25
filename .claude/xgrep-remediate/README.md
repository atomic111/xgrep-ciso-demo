# xgrep Remediate

A Claude Code skill for safely fixing a confirmed xgrep finding using xgrep's
verify/apply harness.

## What it does

- Applies a rule's **deterministic** fix and confirms it cleared the finding
- Drives the **assisted** fix loop: reads the fix contract, authors a byte-span
  edit, verifies it, iterates on the rejection reason, and applies it
- Surfaces **advisory** guidance (e.g. rotate a leaked secret) for hand-fixes
- Never reports a fix without a green re-scan

## How it relates to xgrep-triage

`xgrep-triage` decides *whether* a finding is real (read-only). `xgrep-remediate`
*fixes* a finding you have already confirmed is real (it mutates code, via the
gated `fix apply`). They share investigation methodology but do not hand
off state — remediate is scoped to a single confirmed finding and stands alone.

## Usage

```
# Built-in rules (default)
/xgrep-remediate src/db.py py-sql-injection

# Custom rule pack
/xgrep-remediate src/db.py py-sql-injection --rules security-rules/
```

## Installation

```bash
xgrep skill install xgrep-remediate
# or
claude skill install ./skills/xgrep-remediate
```

## Prerequisites

- `xgrep` CLI must be installed and available in PATH
- The target file must be writable for `fix apply`

## The harness

Every edit passes the same gates before it is written:

1. **Parse-clean** — the patched file must still parse; xgrep never writes code it
   would refuse to report.
2. **Re-scan** — the targeted finding must actually clear, with no new
   equal-or-higher-severity finding in the region touched.
3. **Atomic write** — a temp file is renamed over the target; no partial-write
   window.

The same operations are available over MCP as `fix_verify` / `fix_apply`.
