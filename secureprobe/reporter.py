#!/usr/bin/env python3
"""
SecureProbe v2.0 — Reporter
Handles terminal printing, text reports, and HTML report generation.
"""

from __future__ import annotations

import textwrap
import datetime
from pathlib import Path

try:
    from colorama import Fore, Style
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""

from .scanner import (Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS,
                       SEV_COLOR, SEV_ORDER, SEV_WEIGHT, _now_str)


# ─────────────────────────────────────────────────────────────────────────────
#  TERMINAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
  ___                        ___           _
 / __| ___  __  _  _  _ _  / _ \ _ _  ___| |__  ___
 \__ \/ -_)/ _|| || || '_|| (_) | '_|/ _ \ '_ \/ -_)
 |___/\___|\__| \_,_||_|   \___/|_|  \___/_.__/\___|
  Web Security Audit Tool  v2.0  —  Authorized Use Only
"""

SEV_ICON = {
    CRITICAL: "🔴",
    HIGH:     "🟠",
    MEDIUM:   "🟡",
    LOW:      "🔵",
    INFO:     "⚪",
    PASS:     "✅",
}


def print_banner() -> None:
    print(SEV_COLOR[INFO] + BANNER + Style.RESET_ALL)


def print_finding(f: Finding, verbose: bool = True) -> None:
    color = SEV_COLOR.get(f.severity, "")
    icon  = SEV_ICON.get(f.severity, "•")
    print(f"\n  {icon}  {color}[{f.severity}]{Style.RESET_ALL} "
          f"{Style.BRIGHT}{f.title}{Style.RESET_ALL}")
    if verbose:
        if f.description:
            for line in textwrap.wrap(f.description, width=72):
                print(f"       {line}")
        if f.evidence:
            print(f"       {Fore.CYAN}Evidence :{Style.RESET_ALL} "
                  f"{f.evidence[:160]}")
        if f.remediation:
            lines = f.remediation.splitlines()
            print(f"       {Fore.GREEN}Fix      :{Style.RESET_ALL} {lines[0]}")
            for l in lines[1:]:
                print(f"                {l}")
        if f.reference:
            print(f"       {Style.DIM}Ref      : {f.reference}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
#  TEXT REPORT
# ─────────────────────────────────────────────────────────────────────────────

def generate_text_report(target: str, findings: list[Finding],
                          duration: float, output_path: str | None = None) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS]}
    score  = max(0, 100 - sum(SEV_WEIGHT[s] * counts[s]
                               for s in [CRITICAL, HIGH, MEDIUM, LOW]))
    grade  = _grade(score)

    lines = []
    sep   = "=" * 68

    lines += [
        sep,
        "  SecureProbe v2.0 — Security Audit Report",
        sep,
        f"  Target    : {target}",
        f"  Scanned   : {_now_str()}",
        f"  Duration  : {duration:.1f}s",
        f"  Score     : {score}/100  (Grade: {grade})",
        sep,
        "",
        "  SUMMARY",
        "  " + "-"*30,
        f"  CRITICAL  : {counts[CRITICAL]}",
        f"  HIGH      : {counts[HIGH]}",
        f"  MEDIUM    : {counts[MEDIUM]}",
        f"  LOW       : {counts[LOW]}",
        f"  INFO      : {counts[INFO]}",
        f"  PASSED    : {counts[PASS]}",
        "",
    ]

    # Group by module
    from collections import defaultdict
    by_module: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_module[f.module].append(f)

    for module, mfindings in by_module.items():
        mfindings = sorted(mfindings, key=lambda x: SEV_ORDER[x.severity])
        non_pass  = [f for f in mfindings if f.severity != PASS]
        if not non_pass:
            continue

        lines += [sep, f"  MODULE: {module}", sep]
        for f in non_pass:
            lines += [
                f"  [{f.severity}] {f.title}",
                f"  Description : {f.description[:300]}",
            ]
            if f.evidence:
                lines.append(f"  Evidence    : {f.evidence[:200]}")
            if f.remediation:
                lines.append(f"  Fix         : {f.remediation[:300]}")
            if f.reference:
                lines.append(f"  Reference   : {f.reference}")
            lines.append("")

    lines += [
        sep,
        "  DISCLAIMER",
        sep,
        "  This report is for authorized security assessment only.",
        "  Do not use findings to attack systems you do not own or have",
        "  explicit written permission to test.",
        sep,
    ]

    report = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        print(f"{Fore.GREEN}[+] Text report saved: {output_path}{Style.RESET_ALL}")

    return report


# ─────────────────────────────────────────────────────────────────────────────
#  HTML REPORT
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(target: str, findings: list[Finding],
                          duration: float, output_path: str) -> None:
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS]}
    score  = max(0, 100 - sum(SEV_WEIGHT[s] * counts[s]
                               for s in [CRITICAL, HIGH, MEDIUM, LOW]))
    grade  = _grade(score)
    grade_color = {"A":"#22c55e","B":"#84cc16","C":"#eab308",
                   "D":"#f97316","F":"#ef4444"}.get(grade, "#ef4444")

    sev_colors = {
        CRITICAL: "#ef4444",
        HIGH:     "#f97316",
        MEDIUM:   "#eab308",
        LOW:      "#3b82f6",
        INFO:     "#94a3b8",
        PASS:     "#22c55e",
    }

    def esc(s: str) -> str:
        return (s.replace("&","&amp;").replace("<","&lt;")
                 .replace(">","&gt;").replace('"',"&quot;"))

    rows = ""
    for f in sorted(findings, key=lambda x: SEV_ORDER[x.severity]):
        if f.severity == PASS:
            continue
        color = sev_colors.get(f.severity, "#94a3b8")
        ref_link = (f'<a href="{esc(f.reference)}" target="_blank" '
                    f'rel="noopener">Ref ↗</a>'
                    if f.reference else "")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}20;color:{color};
              border:1px solid {color}40">{esc(f.severity)}</span></td>
          <td><code style="font-size:11px;color:#94a3b8">{esc(f.module)}</code></td>
          <td style="font-weight:600;color:#e2e8f0">{esc(f.title)}</td>
          <td style="color:#94a3b8;font-size:13px">{esc(f.description[:200])}</td>
          <td style="font-size:12px">
            <div style="color:#fbbf24;font-family:monospace;white-space:pre-wrap"
            >{esc(f.evidence[:150])}</div>
            <div style="color:#86efac;margin-top:6px">{esc(f.remediation[:180])}</div>
            <div style="margin-top:4px">{ref_link}</div>
          </td>
        </tr>"""

    score_ring_color = grade_color
    score_desc = {
        "A": "Strong security posture — keep it up.",
        "B": "Good — minor improvements recommended.",
        "C": "Needs attention — several issues to address.",
        "D": "Poor security — significant vulnerabilities present.",
        "F": "Critical risk — immediate action required.",
    }.get(grade, "")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureProbe Report — {esc(target)}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500;600;700&display=swap');

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:      #0a0e1a;
      --surface: #111827;
      --border:  #1e293b;
      --text:    #e2e8f0;
      --muted:   #64748b;
      --accent:  #38bdf8;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', system-ui, sans-serif;
      min-height: 100vh;
      padding: 0 0 60px;
    }}

    .header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      border-bottom: 1px solid var(--border);
      padding: 36px 40px;
      position: relative;
      overflow: hidden;
    }}
    .header::before {{
      content: '';
      position: absolute; inset: 0;
      background: radial-gradient(ellipse 800px 300px at 60% 50%,
                  rgba(56,189,248,.06) 0%, transparent 70%);
    }}
    .header-inner {{
      max-width: 1200px; margin: 0 auto; position: relative;
    }}
    .header h1 {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 22px; font-weight: 700;
      color: var(--accent); letter-spacing: .04em;
      margin-bottom: 4px;
    }}
    .header .target-url {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px; color: var(--muted);
    }}
    .header .meta {{
      font-size: 12px; color: var(--muted); margin-top: 8px;
    }}

    .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 40px; }}

    /* Score + summary row */
    .top-row {{
      display: grid; grid-template-columns: auto 1fr;
      gap: 28px; align-items: start; margin-bottom: 32px;
    }}
    .score-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px 36px;
      display: flex; align-items: center; gap: 24px;
      min-width: 260px;
    }}
    .score-ring {{
      width: 88px; height: 88px;
      border-radius: 50%;
      background: conic-gradient({score_ring_color} {score}%, #1e293b {score}%);
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 0 28px {score_ring_color}30;
      flex-shrink: 0;
    }}
    .score-inner {{
      width: 68px; height: 68px;
      border-radius: 50%;
      background: var(--surface);
      display: flex; align-items: center; justify-content: center;
      flex-direction: column;
    }}
    .score-num {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 22px; font-weight: 700;
      color: {score_ring_color};
      line-height: 1;
    }}
    .score-total {{
      font-size: 10px; color: var(--muted);
    }}
    .score-meta .grade {{
      font-size: 28px; font-weight: 700;
      color: {grade_color};
      font-family: 'JetBrains Mono', monospace;
      line-height: 1;
    }}
    .score-meta .grade-desc {{
      font-size: 12px; color: var(--muted);
      margin-top: 4px; max-width: 140px;
    }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 12px;
    }}
    .sum-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      text-align: center;
    }}
    .sum-num {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 28px; font-weight: 700;
      line-height: 1;
    }}
    .sum-lbl {{
      font-size: 11px; color: var(--muted);
      margin-top: 4px; letter-spacing: .06em;
    }}

    /* Table */
    .table-wrap {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      overflow: hidden;
    }}
    .table-header {{
      padding: 20px 24px;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between;
    }}
    .table-header h2 {{
      font-size: 15px; font-weight: 600; color: var(--text);
    }}
    table {{
      width: 100%; border-collapse: collapse;
    }}
    th {{
      font-size: 11px; color: var(--muted);
      letter-spacing: .08em; text-transform: uppercase;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      text-align: left; background: #0d1525;
    }}
    td {{
      padding: 14px 16px;
      border-bottom: 1px solid {{'#1e293b'}}10;
      vertical-align: top;
      font-size: 13px;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #ffffff04; }}

    .badge {{
      display: inline-block;
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 11px; font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: .04em;
      white-space: nowrap;
    }}

    a {{ color: var(--accent); text-decoration: none; font-size: 12px; }}
    a:hover {{ text-decoration: underline; }}

    .disclaimer {{
      margin-top: 32px;
      background: #1a1008;
      border: 1px solid #78350f40;
      border-radius: 12px;
      padding: 16px 20px;
      font-size: 12px;
      color: #d97706;
      line-height: 1.7;
    }}

    .footer {{
      text-align: center;
      margin-top: 40px;
      font-size: 12px;
      color: var(--muted);
    }}
    .footer span {{ color: var(--accent); }}
  </style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <h1>⚡ SecureProbe v2.0 — Security Audit Report</h1>
    <div class="target-url">{esc(target)}</div>
    <div class="meta">Scanned: {_now_str()} &nbsp;·&nbsp; Duration: {duration:.1f}s &nbsp;·&nbsp;
    Modules: 16 &nbsp;·&nbsp; Findings: {sum(counts[s] for s in [CRITICAL,HIGH,MEDIUM,LOW,INFO])}</div>
  </div>
</div>

<div class="container">

  <div class="top-row">
    <div class="score-card">
      <div class="score-ring">
        <div class="score-inner">
          <div class="score-num">{score}</div>
          <div class="score-total">/100</div>
        </div>
      </div>
      <div class="score-meta">
        <div class="grade">Grade {grade}</div>
        <div class="grade-desc">{score_desc}</div>
      </div>
    </div>

    <div class="summary-grid">
      <div class="sum-card">
        <div class="sum-num" style="color:#ef4444">{counts[CRITICAL]}</div>
        <div class="sum-lbl">CRITICAL</div>
      </div>
      <div class="sum-card">
        <div class="sum-num" style="color:#f97316">{counts[HIGH]}</div>
        <div class="sum-lbl">HIGH</div>
      </div>
      <div class="sum-card">
        <div class="sum-num" style="color:#eab308">{counts[MEDIUM]}</div>
        <div class="sum-lbl">MEDIUM</div>
      </div>
      <div class="sum-card">
        <div class="sum-num" style="color:#3b82f6">{counts[LOW]}</div>
        <div class="sum-lbl">LOW</div>
      </div>
      <div class="sum-card">
        <div class="sum-num" style="color:#94a3b8">{counts[INFO]}</div>
        <div class="sum-lbl">INFO</div>
      </div>
      <div class="sum-card">
        <div class="sum-num" style="color:#22c55e">{counts[PASS]}</div>
        <div class="sum-lbl">PASSED</div>
      </div>
    </div>
  </div>

  <div class="table-wrap">
    <div class="table-header">
      <h2>Findings</h2>
      <span style="font-size:12px;color:var(--muted)">
        {sum(counts[s] for s in [CRITICAL,HIGH,MEDIUM,LOW])} actionable issues
      </span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Module</th>
          <th>Finding</th>
          <th>Description</th>
          <th>Evidence / Fix / Ref</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <div class="disclaimer">
    ⚠ DISCLAIMER: This report is for authorized security assessment only.
    Only use SecureProbe on systems you own or have explicit written permission to test.
    Unauthorized scanning is illegal in most jurisdictions regardless of intent.
  </div>

  <div class="footer">
    Generated by <span>SecureProbe v2.0</span> · {_now_str()}
  </div>

</div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"{Fore.GREEN}[+] HTML report saved: {output_path}{Style.RESET_ALL}")


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 55: return "D"
    return "F"
