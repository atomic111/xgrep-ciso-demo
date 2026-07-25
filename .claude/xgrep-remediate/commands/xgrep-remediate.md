---
name: xgrep-remediate
description: Fix a confirmed xgrep finding using the verify/apply harness
argument-hint: "<file> [rule-id] [--rules <rules-path>]"
allowed-tools: Bash Read Glob Grep
---

# Remediate an xgrep Finding

**Target:** $ARGUMENTS (a file, optionally a rule ID to focus on)

Fix one confirmed finding and prove the fix holds. This assumes the finding is
already a true positive — if you are not sure, triage it first (`/xgrep-triage`).

Commands use xgrep's **built-in rules** by default — no `-f` needed. Only if the
target finding came from a **custom** rule pack, add `-f <rules-path>` to every
`scan` / `fix verify` / `fix apply` command below.

1. **Scan the target file** with context and read the result:
   ```bash
   xgrep scan --json --context 3 <file> > /tmp/xgrep-finding.json
   ```
   Read `/tmp/xgrep-finding.json`. Locate the finding (filter by rule ID if given)
   and note its `extra.fix_info.kind`.

2. **Branch on the tier:**
   - `deterministic` → preview and apply (`scan` discovers, `fix` writes):
     ```bash
     xgrep scan --json <file> | xgrep fix verify --rule <id>   # preview, no write
     xgrep scan --json <file> | xgrep fix apply  --rule <id>   # apply, verified
     ```
   - `assisted` → read `extra.fix_info.contract` (`unsafe_region`, `strategy`,
     `acceptance_criteria`) and run the loop in steps 3–5.
   - `advisory` → read `extra.fix_info.hint`, fix by hand, then re-scan.

3. **Author a candidate edit** as byte-span replacements and verify (never writes):
   ```bash
   echo '{"path":"<file>","rule_id":"<id>","edits":[
     {"start_byte":<s>,"end_byte":<e>,"replacement":"<new code>"}]}' \
     | xgrep fix verify
   ```

4. **Iterate** on `reason` if `accepted` is false (`span-conflict`, `parse-error`,
   `finding-not-cleared`, `new-finding-introduced`, `no-change`) until accepted.

5. **Apply** the accepted candidate (`fix apply` always writes; `fix verify` never does):
   ```bash
   echo '{…candidate…}' | xgrep fix apply
   ```

6. **Confirm** by re-scanning the file; report the finding as fixed only when the
   re-scan is clean, citing the cleared finding.

Invoke the `xgrep-remediate` skill for the full loop, the rejection-reason
playbook, and the fix-contract schema.
