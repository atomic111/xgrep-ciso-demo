#!/usr/bin/env python3
"""Turn an xgrep JSON scan into a CISO-facing HTML dashboard.

Reads the JSON produced by `xgrep scan --json ...` and writes a single,
self-contained HTML file (inline CSS, no external assets) suitable for GitHub
Pages. It classifies findings into three lenses a security leader cares about —
application code (SAST), leaked secrets, and vulnerable dependencies (SCA) —
and leads with an executive summary and a risk posture verdict.

Usage:
    python report/gen_report.py <scan.json> <out.html> [--repo R] [--commit C]
        [--branch B] [--space SPACE_MRN] [--xgrep-version V]

Standard library only, so it runs in CI with nothing to install.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import html
import json
import sys

# xgrep severity -> (CISO label, rank, hex color)
SEV = {
    "CRITICAL": ("Critical", 0, "#b3123b"),
    "ERROR": ("High", 1, "#d9480f"),
    "WARNING": ("Medium", 2, "#b8860b"),
    "INFO": ("Low", 3, "#2b6cb0"),
}
SEV_ORDER = ["CRITICAL", "ERROR", "WARNING", "INFO"]


def classify(finding: dict) -> str:
    """Return one of: dependency, secret, code."""
    extra = finding.get("extra", {})
    if "dependency-vuln" in (extra.get("labels") or []):
        return "dependency"
    if extra.get("metadata", {}).get("category") == "secrets":
        return "secret"
    return "code"


def sev_of(f: dict) -> str:
    return f.get("extra", {}).get("severity", "INFO")


def esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def verdict(counts: collections.Counter) -> tuple[str, str, str]:
    """Return (headline, detail, css_class) for the posture band."""
    crit = counts["CRITICAL"]
    high = counts["ERROR"]
    if crit:
        return (
            "Action required",
            f"{crit} critical and {high} high-severity issue(s) are exploitable and should be remediated before release.",
            "v-bad",
        )
    if high:
        return (
            "Elevated risk",
            f"No critical issues, but {high} high-severity issue(s) need attention.",
            "v-warn",
        )
    if counts["WARNING"]:
        return ("Manageable", "Only medium/low findings remain — schedule into normal hardening work.", "v-ok")
    return ("Clean", "No findings in this scan.", "v-ok")


def kpi(n: int, label: str, color: str) -> str:
    return (
        f'<div class="kpi"><div class="kpi-n" style="color:{color}">{n}</div>'
        f'<div class="kpi-l">{esc(label)}</div></div>'
    )


def sev_badge(sev: str) -> str:
    label, _, color = SEV.get(sev, (sev, 9, "#666"))
    return f'<span class="badge" style="background:{color}">{esc(label)}</span>'


def code_row(f: dict) -> str:
    extra = f["extra"]
    meta = extra.get("metadata", {})
    loc = f'{f["path"]}:{f["start"]["line"]}'
    cwe = ", ".join(meta.get("cwe", [])[:1]) if meta.get("cwe") else ""
    owasp = ", ".join(meta.get("owasp", [])[:1]) if meta.get("owasp") else ""
    tags = " ".join(
        f'<span class="tag">{esc(t)}</span>' for t in filter(None, [cwe, owasp])
    )
    fix = extra.get("fix_info", {}).get("hint") or f.get("remediation", {}).get("description", "")
    return f"""
    <tr>
      <td>{sev_badge(sev_of(f))}</td>
      <td><code>{esc(extra.get("check_id") or f.get("check_id"))}</code></td>
      <td><code class="loc">{esc(loc)}</code></td>
      <td class="msg">{esc(extra.get("message", ""))}{('<div class="tags">' + tags + '</div>') if tags else ''}
          {('<div class="fix"><b>Fix:</b> ' + esc(fix) + '</div>') if fix else ''}</td>
    </tr>"""


def dep_rows(deps: list) -> str:
    # group by package@version
    by_pkg = collections.OrderedDict()
    for d in sorted(deps, key=lambda x: (SEV.get(sev_of(x), ("", 9))[1], x["extra"]["metadata"].get("package", ""))):
        meta = d["extra"]["metadata"]
        key = f'{meta.get("package","?")}@{meta.get("version","?")}'
        by_pkg.setdefault(key, []).append(d)
    out = []
    for pkg, items in by_pkg.items():
        worst = min(items, key=lambda x: SEV.get(sev_of(x), ("", 9))[1])
        advisories = " ".join(
            f'<span class="cve">{esc(i.get("check_id"))}</span>' for i in items
        )
        out.append(
            f"""<tr>
              <td>{sev_badge(sev_of(worst))}</td>
              <td><code>{esc(pkg)}</code></td>
              <td>{len(items)}</td>
              <td class="msg">{advisories}</td>
            </tr>"""
        )
    return "".join(out)


def secret_row(f: dict) -> str:
    extra = f["extra"]
    loc = f'{f["path"]}:{f["start"]["line"]}'
    return f"""
    <tr>
      <td>{sev_badge(sev_of(f))}</td>
      <td><code>{esc(extra.get("check_id") or f.get("check_id"))}</code></td>
      <td><code class="loc">{esc(loc)}</code></td>
      <td class="msg">{esc(extra.get("message",""))}</td>
    </tr>"""


def build(data: dict, args) -> str:
    results = data.get("results", [])
    buckets = {"code": [], "secret": [], "dependency": []}
    for f in results:
        buckets[classify(f)].append(f)

    counts = collections.Counter(sev_of(f) for f in results)
    code_counts = collections.Counter(sev_of(f) for f in buckets["code"])
    head, detail, vclass = verdict(counts)

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    space = args.space or ""
    space_name = space.rsplit("/", 1)[-1] if space else ""
    space_link = (
        f'<a href="https://app.mondoo.com/space/overview?spaceId={esc(space_name)}&region=US">{esc(space_name)}</a>'
        if space_name
        else "—"
    )

    # Top risks = code findings CRITICAL/ERROR, sorted worst-first
    top = sorted(
        [f for f in buckets["code"] if sev_of(f) in ("CRITICAL", "ERROR")],
        key=lambda x: SEV.get(sev_of(x), ("", 9))[1],
    )

    kpis = "".join(
        kpi(counts.get(s, 0), SEV[s][0], SEV[s][2]) for s in SEV_ORDER
    )

    top_cards = "".join(
        f"""<div class="card">
              <div class="card-h">{sev_badge(sev_of(f))}
                <code>{esc(f['extra'].get('check_id') or f.get('check_id'))}</code></div>
              <div class="card-loc"><code>{esc(f['path'])}:{esc(f['start']['line'])}</code></div>
              <div class="card-msg">{esc(f['extra'].get('message',''))}</div>
              {('<div class="fix"><b>Remediation:</b> ' + esc(f['extra'].get('fix_info',{}).get('hint','') or f.get('remediation',{}).get('description','')) + '</div>')}
            </div>"""
        for f in top[:8]
    ) or '<p class="empty">No critical or high code findings. 🎉</p>'

    code_table = "".join(code_row(f) for f in sorted(buckets["code"], key=lambda x: SEV.get(sev_of(x), ("", 9))[1])) or '<tr><td colspan="4" class="empty">None</td></tr>'
    secret_table = "".join(secret_row(f) for f in buckets["secret"]) or '<tr><td colspan="4" class="empty">None</td></tr>'
    dep_table = dep_rows(buckets["dependency"]) or '<tr><td colspan="4" class="empty">None</td></tr>'

    scanned = data.get("paths", {}).get("scanned", [])

    return TEMPLATE.format(
        repo=esc(args.repo or "acme-devops-toolkit"),
        branch=esc(args.branch or "main"),
        commit=esc((args.commit or "")[:10]),
        now=now,
        xgrep_version=esc(args.xgrep_version or data.get("version", "")),
        space_link=space_link,
        vclass=vclass,
        vhead=esc(head),
        vdetail=esc(detail),
        total=len(results),
        kpis=kpis,
        n_code=len(buckets["code"]),
        n_secret=len(buckets["secret"]),
        n_dep=len(buckets["dependency"]),
        top_cards=top_cards,
        code_table=code_table,
        secret_table=secret_table,
        dep_table=dep_table,
        n_files=len(scanned),
    )


TEMPLATE = """<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Posture — {repo}</title>
<style>
  :root {{
    --bg:#f6f7f9; --panel:#ffffff; --ink:#1a1d21; --muted:#5b6470;
    --line:#e4e7ec; --accent:#0b5cff; --code:#f2f4f7;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#0f1115; --panel:#171a21; --ink:#e8eaed; --muted:#9aa4b2;
             --line:#262b34; --accent:#5b8cff; --code:#1e222b; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1060px; margin:0 auto; padding:32px 20px 80px; }}
  header.top {{ display:flex; flex-wrap:wrap; justify-content:space-between; align-items:flex-end; gap:16px; margin-bottom:8px; }}
  .brand {{ font-size:13px; letter-spacing:.14em; text-transform:uppercase; color:var(--muted); }}
  h1 {{ font-size:28px; margin:4px 0 0; }}
  .meta {{ color:var(--muted); font-size:13px; text-align:right; }}
  .meta code {{ color:var(--ink); }}
  .verdict {{ border-radius:14px; padding:20px 22px; margin:22px 0; color:#fff; }}
  .verdict h2 {{ margin:0 0 4px; font-size:22px; }}
  .verdict p {{ margin:0; opacity:.95; }}
  .v-bad {{ background:linear-gradient(135deg,#b3123b,#7a0b28); }}
  .v-warn {{ background:linear-gradient(135deg,#d9480f,#a3370b); }}
  .v-ok {{ background:linear-gradient(135deg,#1e7d46,#155e34); }}
  .kpis {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:18px 0; }}
  .kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; text-align:center; }}
  .kpi-n {{ font-size:34px; font-weight:700; line-height:1; }}
  .kpi-l {{ color:var(--muted); font-size:13px; margin-top:6px; }}
  .lenses {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin:12px 0 26px; }}
  .lens {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }}
  .lens b {{ font-size:22px; }} .lens span {{ color:var(--muted); font-size:13px; }}
  section {{ margin:30px 0; }}
  h3 {{ font-size:17px; border-bottom:1px solid var(--line); padding-bottom:8px; }}
  .cards {{ display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }}
  @media (max-width:720px) {{ .cards,.kpis,.lenses {{ grid-template-columns:1fr 1fr; }} }}
  @media (max-width:520px) {{ .cards,.kpis,.lenses {{ grid-template-columns:1fr; }} }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-left:4px solid #b3123b; border-radius:10px; padding:14px; }}
  .card-h {{ display:flex; align-items:center; gap:8px; }}
  .card-loc {{ color:var(--muted); font-size:13px; margin:6px 0; }}
  .card-msg {{ font-size:14px; }}
  .fix {{ margin-top:8px; font-size:13px; background:var(--code); border-radius:8px; padding:8px 10px; }}
  .tblwrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:12px; }}
  table {{ border-collapse:collapse; width:100%; background:var(--panel); font-size:14px; }}
  th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
  tr:last-child td {{ border-bottom:none; }}
  code {{ background:var(--code); padding:1px 5px; border-radius:5px; font-size:12.5px; }}
  code.loc {{ white-space:nowrap; }}
  .badge {{ color:#fff; padding:2px 9px; border-radius:20px; font-size:12px; font-weight:600; white-space:nowrap; }}
  .tag {{ display:inline-block; background:var(--code); color:var(--muted); border-radius:6px; padding:1px 7px; font-size:11.5px; margin:4px 4px 0 0; }}
  .cve {{ display:inline-block; background:var(--code); border-radius:6px; padding:1px 7px; font-size:12px; margin:2px 4px 2px 0; }}
  .tags {{ margin-top:6px; }}
  .empty {{ color:var(--muted); text-align:center; padding:16px; }}
  footer {{ margin-top:50px; color:var(--muted); font-size:13px; border-top:1px solid var(--line); padding-top:16px; }}
  a {{ color:var(--accent); }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <div class="brand">Application Security Report</div>
      <h1>{repo}</h1>
    </div>
    <div class="meta">
      Scanned <code>{now}</code><br>
      Branch <code>{branch}</code> · Commit <code>{commit}</code><br>
      Engine <code>xgrep {xgrep_version}</code> · Mondoo space {space_link}
    </div>
  </header>

  <div class="verdict {vclass}">
    <h2>{vhead}</h2>
    <p>{vdetail} &nbsp;·&nbsp; {total} findings this scan.</p>
  </div>

  <div class="kpis">{kpis}</div>

  <div class="lenses">
    <div class="lens"><b>{n_code}</b><br><span>Application code (SAST)</span></div>
    <div class="lens"><b>{n_secret}</b><br><span>Leaked secrets</span></div>
    <div class="lens"><b>{n_dep}</b><br><span>Vulnerable dependencies (SCA)</span></div>
  </div>

  <section>
    <h3>Top exploitable risks</h3>
    <p style="color:var(--muted);margin-top:4px">Highest-severity application-code findings — each proven by data-flow (taint) analysis from untrusted input to a dangerous operation.</p>
    <div class="cards">{top_cards}</div>
  </section>

  <section>
    <h3>Application code findings (SAST)</h3>
    <div class="tblwrap"><table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Detail &amp; remediation</th></tr></thead>
      <tbody>{code_table}</tbody>
    </table></div>
  </section>

  <section>
    <h3>Leaked secrets</h3>
    <div class="tblwrap"><table>
      <thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Detail</th></tr></thead>
      <tbody>{secret_table}</tbody>
    </table></div>
  </section>

  <section>
    <h3>Vulnerable dependencies (SCA)</h3>
    <p style="color:var(--muted);margin-top:4px">Known CVEs and End-of-Life packages from the resolved dependency lockfile, checked against Mondoo's vulnerability database.</p>
    <div class="tblwrap"><table>
      <thead><tr><th>Severity</th><th>Package</th><th>Advisories</th><th>CVE / GHSA IDs</th></tr></thead>
      <tbody>{dep_table}</tbody>
    </table></div>
  </section>

  <footer>
    Generated by <a href="https://github.com/mondoohq/xgrep">xgrep</a> — Mondoo's Semgrep-compatible SAST scanner —
    across {n_files} scanned files. Findings also published to Mondoo Platform for tracking over time.
    This report covers an <b>intentionally vulnerable demo application</b>.
  </footer>
</div>
</body>
</html>"""


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("scan_json")
    p.add_argument("out_html")
    p.add_argument("--repo")
    p.add_argument("--commit")
    p.add_argument("--branch")
    p.add_argument("--space")
    p.add_argument("--xgrep-version", dest="xgrep_version")
    args = p.parse_args(argv)

    with open(args.scan_json) as fh:
        data = json.load(fh)
    html_out = build(data, args)
    with open(args.out_html, "w") as fh:
        fh.write(html_out)
    print(f"wrote {args.out_html} ({len(data.get('results', []))} findings)")


if __name__ == "__main__":
    sys.exit(main())
