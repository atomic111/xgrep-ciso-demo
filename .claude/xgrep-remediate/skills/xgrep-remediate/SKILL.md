---
name: xgrep-remediate
description: Fixes a confirmed xgrep finding safely using the verify/apply harness — applies deterministic fixes, authors and verifies assisted fixes against the fix contract, and surfaces advisory guidance. Use to remediate a specific finding you already believe is a true positive.
allowed-tools: Bash Read Glob Grep
---

# xgrep Remediate

Fix a confirmed xgrep finding and **prove the fix holds** with xgrep's verify/apply
harness. xgrep owns the mechanical gates (parse-clean, re-scan, atomic write); you
own the reasoning that authors the edit.

## When to Use

- Fixing a specific finding you already believe is a real, exploitable bug
- Driving the assisted fix loop: author an edit, verify it, iterate on rejections
- Applying a rule's deterministic fix and confirming it cleared the finding

## When NOT to Use

- Deciding *whether* a finding is real — that is triage. Use `xgrep-triage` first;
  this skill assumes the finding is a confirmed true positive.
- Suppressing or ignoring a finding instead of fixing it
- Creating or modifying rules (use `xgrep-rule-creator`)

This skill is **scoped to a finding**, not a scan: you remediate one confirmed
issue (a file + rule, or a single finding), not a whole codebase at once. It never
depends on a prior triage *run* — there is no state handed between skills. When you
need to confirm exploitability before fixing, apply the triage investigation
patterns inline (see `xgrep-triage`), then proceed here.

**Rules are built in.** Every command below uses xgrep's bundled rules by default
(600+ across 14 languages, filtered to security + secrets) — no `-f` needed. Pass
`-f <rules-path>` only when you are remediating findings from a *custom* rule pack;
in that case add the same `-f` to every `scan` / `fix verify` / `fix apply`
command so the re-scan gate uses the rule that produced the finding.

## The three fix tiers

Every fixable finding carries a confidence in `extra.fix_info.kind` (ADR-0230).
The tier decides who authors the edit:

- **`deterministic`** — xgrep already computed the exact edit. `scan` emits it; the
  write-only `fix` command applies it through the harness (ADR-0257). `scan` never
  mutates source — `fix` does:
  ```bash
  xgrep scan --json <target> | xgrep fix verify   # preview the diffs (no write)
  xgrep scan --json <target> | xgrep fix apply    # apply, verified + atomic
  ```
  Or rely on the cache `scan` writes — `xgrep scan <target>` then `xgrep fix apply`
  (reads `.xgrep/findings.json`). Scope with `--rule <id>`, `--min-confidence`,
  `--max-severity`; add `--strict` to exit non-zero on any rejected fix. The re-scan
  gate runs by default (`--no-rescan` skips it). `fix` reports each finding's
  disposition as a `FixOutcome` (`applied` / `verified` / `rejected` / `needs-agent`
  / `advisory` / `out-of-scope` / `stale-cache`).

- **`assisted`** — a finding xgrep cannot fix mechanically. It emits a **fix
  contract** and verifies whatever edit you return. This is your loop (below).

- **`advisory`** — guidance only (`extra.fix_info.hint`, e.g. "rotate the secret").
  Read the hint, fix by hand, then re-scan to confirm the finding is gone.

## The assisted loop

### Step 1: Scan the target and read the contract

Scan just the file (or small scope) holding the finding, with context:

```bash
xgrep scan --json --context 3 <file> > /tmp/xgrep-finding.json
```

Read `/tmp/xgrep-finding.json`. For an `assisted` finding, `extra.fix_info.contract`
gives you:

- `unsafe_region` — the byte/line span to change, and its enclosing `function`.
- `strategy` — the natural-language approach (the rule's fix-hint).
- `acceptance_criteria` — what xgrep will mechanically verify on your edit.

The evidence rides on the same result: `dataflow_trace` (source → sink) and
`context` (surrounding code, callers/callees). See
[fix-contract-reference.md]({baseDir}/references/fix-contract-reference.md) for the
full schema.

### Step 2: Understand before editing

Read the file around `unsafe_region`. If you need types, imports, or the flow,
investigate with the code graph (the same tools `xgrep-triage` uses):

```bash
xgrep graph context <function-name> --depth 2
xgrep graph paths <entry-point> <dangerous-sink>
```

### Step 3: Author a candidate edit

Express the fix as **byte-span replacements** over the file. The candidate is a
JSON object on stdin (`path`, `rule_id`, `edits`):

```bash
echo '{"path":"src/db.py","rule_id":"py-sql-injection","edits":[
  {"start_byte":420,"end_byte":480,"replacement":"cur.execute(\"… WHERE id=%s\", (uid,))"}
]}' | xgrep fix verify
```

`fix verify` **never writes** — it returns a verdict with a unified-`diff` preview.
(Add `-f <rules-path>` here too if the finding came from a custom rule pack.)

### Step 4: Iterate on the rejection reason

If `accepted` is false, `reason` is one of `span-conflict`, `parse-error`,
`finding-not-cleared`, `new-finding-introduced`, or `no-change`. Each has a
concrete next move — see the rejection-reason playbook in
[remediation-loop.md]({baseDir}/references/remediation-loop.md). Adjust the edit and
re-verify. This is a closed loop: xgrep never writes an unverified edit.

### Step 5: Apply when accepted

`fix verify` checks read-only; `fix apply` writes the accepted edit (gated by the
same harness, atomic write). Use `verify` to iterate, then `apply` once to commit:

```bash
echo '{…candidate…}' | xgrep fix apply
```

### Step 6: Confirm

Re-scan the file and verify the finding is gone (and no new equal-or-higher
finding appeared). Report the cleared finding with its fingerprint as evidence —
never report a fix without a green re-scan.

## Over MCP

The same operations are available as the `fix_verify` (read-only) and `fix_apply`
(writes the accepted edit) tools. Both run the identical harness, so a rejected
candidate is never written; use `fix_verify` to iterate and `fix_apply` to commit.

## References

- Remediation loop & rejection-reason playbook: [remediation-loop.md]({baseDir}/references/remediation-loop.md)
- Fix-contract & fix_info schema: [fix-contract-reference.md]({baseDir}/references/fix-contract-reference.md)

## Tips

- Remediate one finding at a time; verify each before moving on.
- Prefer the smallest edit that satisfies the `acceptance_criteria` — a tight span
  is less likely to hit `span-conflict` or `new-finding-introduced`.
- `deterministic` fixes need no loop — `scan --json … | fix verify` to preview,
  then `fix apply` to write.
- For `advisory` secrets, the real fix is rotation + history purge, not a code
  edit; the hint says so.
