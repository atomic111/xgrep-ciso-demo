#!/usr/bin/env python3
"""Turn an xgrep JSON scan into a CISO-facing HTML dashboard (Mondoo-branded).

Reads the JSON produced by `xgrep scan --json ...` and writes a single,
self-contained HTML file — Mondoo brand colors, the Mondoo wordmark, and the
Mona Sans / IBM Plex Mono brand fonts all inlined as data URIs, so it renders
identically on GitHub Pages with no external requests. Light mode.

It classifies findings into three lenses a security leader cares about —
application code (SAST), leaked secrets, and vulnerable dependencies (SCA) —
and leads with an executive summary and a risk posture verdict.

Usage:
    python report/gen_report.py <scan.json> <out.html> [--repo R] [--commit C]
        [--branch B] [--space SPACE_MRN] [--xgrep-version V]

Standard library only, so it runs in CI with nothing to install.
"""
from __future__ import annotations

import argparse
import base64
import collections
import datetime
import html
import json
import os
import sys

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

# --- Mondoo brand palette (from brand/color.tokens.json) --------------------
UV = "#542C84"        # Ultraviolet — primary brand
RACING_RED = "#DB4437"
SPEED_YELLOW = "#F4B400"
MARITIME_BLUE = "#4C7CD4"
AURATIUM_GREEN = "#5B8C5A"

# xgrep severity -> (CISO label, rank, badge bg, badge text, KPI-number color)
SEV = {
    "CRITICAL": ("Critical", 0, "#B3122F", "#ffffff", "#B3122F"),
    "ERROR": ("High", 1, RACING_RED, "#ffffff", RACING_RED),
    "WARNING": ("Medium", 2, SPEED_YELLOW, "#0C0D15", "#B07E00"),
    "INFO": ("Low", 3, MARITIME_BLUE, "#ffffff", MARITIME_BLUE),
}
SEV_ORDER = ["CRITICAL", "ERROR", "WARNING", "INFO"]


def _data_uri(path: str, mime: str) -> str:
    try:
        with open(path, "rb") as fh:
            return f"data:{mime};base64," + base64.b64encode(fh.read()).decode()
    except OSError:
        return ""


def _font_faces() -> str:
    faces = [
        ("Mona Sans", 400, "MonaSans-Regular.ttf"),
        ("Mona Sans", 700, "MonaSans-Bold.ttf"),
        ("IBM Plex Mono", 400, "IBMPlexMono-Regular.ttf"),
    ]
    out = []
    for family, weight, fname in faces:
        uri = _data_uri(os.path.join(ASSETS, "fonts", fname), "font/ttf")
        if not uri:
            continue
        out.append(
            f"@font-face{{font-family:'{family}';font-style:normal;"
            f"font-weight:{weight};font-display:swap;src:url({uri}) format('truetype');}}"
        )
    return "\n".join(out)


def classify(finding: dict) -> str:
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
    crit = counts["CRITICAL"]
    high = counts["ERROR"]
    if crit:
        return (
            "Action required",
            f"{crit} critical and {high} high-severity issue(s) are exploitable and should be remediated before release.",
            "v-bad",
        )
    if high:
        return ("Elevated risk", f"No critical issues, but {high} high-severity issue(s) need attention.", "v-warn")
    if counts["WARNING"]:
        return ("Manageable", "Only medium/low findings remain — schedule into normal hardening work.", "v-ok")
    return ("Clean", "No findings in this scan.", "v-ok")


def kpi(n: int, label: str, color: str) -> str:
    return (
        f'<div class="kpi"><div class="kpi-n" style="color:{color}">{n}</div>'
        f'<div class="kpi-l">{esc(label)}</div></div>'
    )


def sev_badge(sev: str) -> str:
    label, _, bg, fg, _num = SEV.get(sev, (sev, 9, "#747679", "#fff", "#747679"))
    return f'<span class="badge" style="background:{bg};color:{fg}">{esc(label)}</span>'


def code_row(f: dict) -> str:
    extra = f["extra"]
    meta = extra.get("metadata", {})
    loc = f'{f["path"]}:{f["start"]["line"]}'
    cwe = ", ".join(meta.get("cwe", [])[:1]) if meta.get("cwe") else ""
    owasp = ", ".join(meta.get("owasp", [])[:1]) if meta.get("owasp") else ""
    tags = " ".join(f'<span class="tag">{esc(t)}</span>' for t in filter(None, [cwe, owasp]))
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
    by_pkg = collections.OrderedDict()
    for d in sorted(deps, key=lambda x: (SEV.get(sev_of(x), ("", 9))[1], x["extra"]["metadata"].get("package", ""))):
        meta = d["extra"]["metadata"]
        key = f'{meta.get("package","?")}@{meta.get("version","?")}'
        by_pkg.setdefault(key, []).append(d)
    out = []
    for pkg, items in by_pkg.items():
        worst = min(items, key=lambda x: SEV.get(sev_of(x), ("", 9))[1])
        advisories = " ".join(f'<span class="cve">{esc(i.get("check_id"))}</span>' for i in items)
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
    head, detail, vclass = verdict(counts)

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    space = args.space or ""
    space_name = space.rsplit("/", 1)[-1] if space else ""
    space_link = (
        f'<a href="https://app.mondoo.com/space/overview?spaceId={esc(space_name)}&region=US">{esc(space_name)}</a>'
        if space_name
        else "—"
    )

    top = sorted(
        [f for f in buckets["code"] if sev_of(f) in ("CRITICAL", "ERROR")],
        key=lambda x: SEV.get(sev_of(x), ("", 9))[1],
    )

    kpis = "".join(kpi(counts.get(s, 0), SEV[s][0], SEV[s][4]) for s in SEV_ORDER)

    top_cards = "".join(
        f"""<div class="card" style="border-left-color:{SEV.get(sev_of(f), ('', 9, '#747679'))[2]}">
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
    logo = _data_uri(os.path.join(ASSETS, "mondoo-logo-white.png"), "image/png")
    logo_html = (
        f'<img class="logo" src="{logo}" alt="Mondoo">'
        if logo
        else '<span class="logo-text">mondoo</span>'
    )

    return TEMPLATE.format(
        font_faces=_font_faces(),
        logo=logo_html,
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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Posture — {repo}</title>
<style>
  {font_faces}
  :root {{
    --uv:#542C84; --uv-dark:#3d2061;
    --bg:#FCFBFA; --panel:#FFFFFF; --panel-2:#F5F3F0;
    --ink:#0C0D15; --ink-2:#2E2F32; --muted:#747679;
    --line:#EDEAE5; --line-2:#D8D5D0;
    --crit:#B3122F; --high:#DB4437; --med:#F4B400; --low:#4C7CD4; --ok:#5B8C5A;
  }}
  * {{ box-sizing:border-box; }}
  html {{ background:var(--bg); }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font-family:'Mona Sans',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:15px; line-height:1.55; -webkit-font-smoothing:antialiased; }}
  .brandbar {{ background:var(--uv); color:#fff; }}
  .brandbar .inner {{ max-width:1060px; margin:0 auto; padding:16px 20px;
    display:flex; align-items:center; justify-content:space-between; gap:16px; }}
  .logo {{ height:28px; width:auto; display:block; }}
  .logo-text {{ font-weight:700; font-size:22px; letter-spacing:-.01em; }}
  .brandbar .tagline {{ font-size:12px; letter-spacing:.16em; text-transform:uppercase; opacity:.85; }}
  .wrap {{ max-width:1060px; margin:0 auto; padding:28px 20px 80px; }}
  header.top {{ display:flex; flex-wrap:wrap; justify-content:space-between; align-items:flex-end; gap:16px; }}
  h1 {{ font-size:28px; font-weight:700; margin:6px 0 0; letter-spacing:-.02em; }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .meta {{ color:var(--muted); font-size:13px; text-align:right; }}
  .meta code {{ color:var(--ink-2); }}
  .verdict {{ border-radius:14px; padding:20px 22px; margin:22px 0; color:#fff; }}
  .verdict h2 {{ margin:0 0 4px; font-size:22px; font-weight:700; }}
  .verdict p {{ margin:0; opacity:.96; }}
  .v-bad {{ background:linear-gradient(135deg,#DB4437,#8f0f26); }}
  .v-warn {{ background:linear-gradient(135deg,#F4B400,#b8860b); color:#241a00; }}
  .v-ok {{ background:linear-gradient(135deg,#5B8C5A,#3f6b3e); }}
  .kpis {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:18px 0; }}
  .kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; text-align:center;
    box-shadow:0 1px 2px rgba(12,13,21,.04); }}
  .kpi-n {{ font-size:36px; font-weight:700; line-height:1; }}
  .kpi-l {{ color:var(--muted); font-size:13px; margin-top:6px; }}
  .lenses {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin:12px 0 26px; }}
  .lens {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }}
  .lens b {{ font-size:24px; font-weight:700; }} .lens span {{ color:var(--muted); font-size:13px; }}
  section {{ margin:30px 0; }}
  h3 {{ font-size:17px; font-weight:700; border-bottom:2px solid var(--uv); padding-bottom:8px; display:inline-block; }}
  .hint {{ color:var(--muted); margin-top:6px; }}
  .cards {{ display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }}
  @media (max-width:720px) {{ .cards,.kpis,.lenses {{ grid-template-columns:1fr 1fr; }} }}
  @media (max-width:520px) {{ .cards,.kpis,.lenses {{ grid-template-columns:1fr; }} }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--crit); border-radius:10px; padding:14px;
    box-shadow:0 1px 2px rgba(12,13,21,.04); }}
  .card-h {{ display:flex; align-items:center; gap:8px; }}
  .card-loc {{ color:var(--muted); font-size:13px; margin:6px 0; }}
  .card-msg {{ font-size:14px; }}
  .fix {{ margin-top:8px; font-size:13px; background:var(--panel-2); border-radius:8px; padding:8px 10px; }}
  .tblwrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:12px; margin-top:12px; }}
  table {{ border-collapse:collapse; width:100%; background:var(--panel); font-size:14px; }}
  th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--muted); font-weight:700; font-size:12px; text-transform:uppercase; letter-spacing:.05em; background:var(--panel-2); }}
  tr:last-child td {{ border-bottom:none; }}
  code {{ font-family:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    background:var(--panel-2); padding:1px 5px; border-radius:5px; font-size:12.5px; color:var(--ink-2); }}
  code.loc {{ white-space:nowrap; }}
  .badge {{ padding:2px 9px; border-radius:20px; font-size:12px; font-weight:700; white-space:nowrap; }}
  .tag {{ display:inline-block; background:var(--panel-2); color:var(--muted); border-radius:6px; padding:1px 7px; font-size:11.5px; margin:4px 4px 0 0; }}
  .cve {{ display:inline-block; font-family:'IBM Plex Mono',monospace; background:var(--panel-2); border-radius:6px; padding:1px 7px; font-size:12px; margin:2px 4px 2px 0; }}
  .tags {{ margin-top:6px; }}
  .empty {{ color:var(--muted); text-align:center; padding:16px; }}
  footer {{ margin-top:50px; color:var(--muted); font-size:13px; border-top:1px solid var(--line); padding-top:16px; }}
  a {{ color:var(--uv); font-weight:600; }}
</style>
</head>
<body>
  <div class="brandbar">
    <div class="inner">
      {logo}
      <span class="tagline">Application Security Report</span>
    </div>
  </div>
<div class="wrap">
  <header class="top">
    <div>
      <h1>{repo}</h1>
      <div class="sub">Powered by xgrep — Mondoo's Semgrep-compatible SAST scanner</div>
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
    <p class="hint">Highest-severity application-code findings — each proven by data-flow (taint) analysis from untrusted input to a dangerous operation.</p>
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
    <p class="hint">Known CVEs and End-of-Life packages from the resolved dependency lockfile, checked against Mondoo's vulnerability database.</p>
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
