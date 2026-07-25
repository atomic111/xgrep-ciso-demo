# Example AI triage report

This is an illustrative example of what the bundled **`xgrep-triage`** Claude
Code skill produces when you open this repo in Claude Code and ask:

> "Triage the xgrep findings in this repo."

The skill runs a scan, then for each finding walks xgrep's code graph
(definitions, references, reachability) to decide whether untrusted input can
actually reach the sink — classifying each as a **true positive**, **false
positive**, or **needs review**. Only confirmed true positives are handed to
`xgrep-fix`.

> The verdicts below are an example of the format, not a live run.

---

## Summary

| Verdict | Count |
|---------|-------|
| ✅ True positive (exploitable) | 9 |
| ⚠️ Needs review | 2 |
| ❌ False positive | 0 |

## Findings

### ✅ `python-command-injection` — `app/backup.py:28` — TRUE POSITIVE

`request.form["name"]` (untrusted) flows unmodified through `create_archive` →
`_run_tar`, where it is concatenated into a `shell=True` command. No validation
or escaping on the path. **Reachable and exploitable.** → hand to `xgrep-fix`.

### ✅ `python-sql-injection` — `app/directory.py:25` — TRUE POSITIVE

`request.args["name"]` is interpolated into the query string with `%`. The
sibling `find_user_safe` uses a parameterized query and is correctly **not**
flagged, which confirms the engine is distinguishing the two. **Exploitable.**

### ✅ `python-code-injection` / `python-unsafe-deserialization` — `app/plugins.py` — TRUE POSITIVE

Both the pickle payload and the `eval` expression come straight from the request
body with no gate. Either is direct RCE. **Exploitable.**

### ✅ `python-ssrf-request` + `python-disabled-cert-validation` — `app/proxy.py:28` — TRUE POSITIVE

`request.args["url"]` reaches `requests.get(url, verify=False)`. An attacker
controls the destination *and* TLS verification is off. Confirm the egress
allowlist is absent (it is). **Exploitable** — reachable to internal services
and the cloud metadata endpoint.

### ✅ `python-jwt-algorithm-confusion` — `app/auth.py:26` — TRUE POSITIVE

`verify_signature=False` and `none` in the algorithms list means forged tokens
are accepted. Auth bypass. **Exploitable.**

### ⚠️ `python-debug-enabled` — `app/server.py:37` — NEEDS REVIEW

Only reachable if the module is run directly in production. Real risk, but
severity depends on deployment. Confirm the container entrypoint before rating.

### ⚠️ `acme-direct-requests-usage` — `app/proxy.py:28` — NEEDS REVIEW (policy)

Not a vulnerability per se — a policy violation from the custom Acme rule. Route
through `acme_http` to satisfy the egress-control standard.

## Recommended next step

```
Fix the confirmed true positives.
```

`xgrep-fix` will apply deterministic fixes where available, author-and-verify
assisted fixes against the fix contract for the rest, and **re-scan to prove**
each finding no longer fires.
