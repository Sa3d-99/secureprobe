# ⚡ SecureProbe v2.0

**A professional web security audit tool.** Scan your own web servers and applications for real security weaknesses across 16 modules — get color-coded terminal output or a full HTML report with a security score.

> ⚠ **For authorized use only.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.

---

## Features

- **16 scan modules** — headers, SSL/TLS, CORS, cookies, 70+ sensitive file paths, HTTP methods, open redirect, directory listing, rate limiting, info disclosure, clickjacking, host header injection, mixed content, and more
- **Active probing** — doesn't just check headers; actually sends crafted requests to verify issues (CORS origin reflection, TRACE echo, PUT write test, rate-limit under rapid fire, host header poisoning, error disclosure via probe requests)
- **Smart deduplication** — same finding from multiple sub-checks appears only once, with the highest severity kept
- **HTML report** — dark-theme dashboard with security score, grade (A–F), color-coded summary cards, and full findings table
- **Text report** — plain `.txt` for tickets and email
- **pip installable** — `pip install secureprobe` → `secureprobe <url>` works anywhere

---

## Install

### From PyPI (once published)
```bash
pip install secureprobe
```

### From source (GitHub)
```bash
git clone https://github.com/Sa3d-99/secureprobe.git
cd secureprobe
pip install .
```

### Development install (editable)
```bash
pip install -e ".[dev]"
```

**Dependencies:** `requests`, `colorama`, `urllib3` — everything else is Python stdlib.

---

## Usage

```bash
# Basic scan — color output in terminal
secureprobe https://yoursite.com

# Save as HTML report (open in any browser)
secureprobe https://yoursite.com --output report.html

# Save as plain text report
secureprobe https://yoursite.com --output report.txt

# Deep scan — more paths, longer timeouts
secureprobe https://yoursite.com --deep --output report.html

# Quiet mode — summary only, no per-finding details in terminal
secureprobe https://yoursite.com --output report.html --quiet

# Scan local server or internal IP
secureprobe http://192.168.1.100 --output audit.html

# Also works as a Python module
python -m secureprobe https://yoursite.com --output report.html
```

---

## Scan Modules (16)

| Module | What it checks |
|---|---|
| **Security Headers** | CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, version disclosure, cache-control |
| **SSL/TLS** | Certificate expiry, weak ciphers, short key length, self-signed, legacy TLS 1.0/1.1 support actively probed |
| **CORS Policy** | Wildcard+credentials, reflected origins, null origin bypass, subdomain/prefix spoofing |
| **Cookie Security** | HttpOnly, Secure, SameSite per-cookie; SameSite=None without Secure; session cookie expiry |
| **Sensitive File Exposure** | 70+ paths: `.env`, `.git`, `wp-config`, SQL dumps, actuators, admin panels, API docs, Dockerfiles, log files |
| **HTTP Methods** | TRACE actively verified (echo check), PUT write-test, dangerous methods via OPTIONS |
| **Open Redirect** | 18 parameters × bypass variants (protocol-relative, auth@ tricks) |
| **Directory Listing** | 15+ common directories probed for index listings |
| **Redirect Chain** | HTTP→HTTPS enforcement, mixed-content hops, long chains |
| **Rate Limiting** | 20 rapid requests to main URL + login endpoint detection + POST brute-force check |
| **Subresource Integrity** | External scripts/stylesheets missing SRI hashes |
| **Information Disclosure** | Stack traces, SQL errors, PHP errors, internal IPs, AWS IMDS URL — triggered via probe requests |
| **Clickjacking** | Frame-ancestors / X-Frame-Options validated on HTML responses |
| **Host Header Injection** | Forged Host header reflected in body, Location, or Link headers |
| **Mixed Content** | HTTP resources on HTTPS pages (src/href/action attributes) |
| **Content-Type** | Missing header, missing charset on HTML responses |

---

## Severity Levels & Scoring

| Level | Meaning | Score Impact |
|---|---|---|
| 🔴 CRITICAL | Immediate exploitation risk | −15 |
| 🟠 HIGH | Serious vulnerability | −8 |
| 🟡 MEDIUM | Moderate risk | −4 |
| 🔵 LOW | Minor / hardening | −1 |
| ⚪ INFO | Informational | 0 |
| ✅ PASS | Check passed | 0 |

Score starts at 100. Grade: **A** (90–100) · **B** (80–89) · **C** (70–79) · **D** (55–69) · **F** (0–54)

---

## Example Terminal Output

```
  ___                        ___           _
 / __| ___  __  _  _  _ _  / _ \ _ _  ___| |__  ___
 \__ \/ -_)/ _|| || || '_|| (_) | '_|/ _ \ '_ \/ -_)
 |___/\___|\__| \_,_||_|   \___/|_|  \___/_.__/\___|
  Web Security Audit Tool  v2.0  —  Authorized Use Only

[*] Target  : https://example.com
[*] Host    : example.com:443
[*] Mode    : Standard
[*] Started : 2026-06-02 14:32:00 UTC

[~] Connecting...
    HTTP 200  |  Server: nginx  |  Content-Type: text/html; charset=utf-8

[~] Security Headers...

  🟠  [HIGH] Missing HTTP Strict Transport Security (HSTS)
       No HSTS header. Browsers will not enforce HTTPS, allowing protocol-
       downgrade (SSLstrip) attacks.
       Evidence : Strict-Transport-Security absent
       Fix      : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
       Ref      : https://hstspreload.org/

  ✅ X-Content-Type-Options: nosniff

[~] SSL/TLS Configuration...
  ✅ TLS Protocol: TLSv1.3
  ✅ Cipher: TLS_AES_256_GCM_SHA384
  ✅ Certificate valid for 180 days

==============================================================
  SCAN COMPLETE  —  8.3s
==============================================================
  Score    : 71/100
  CRITICAL : 0
  HIGH     : 2
  MEDIUM   : 4
  LOW      : 6
  PASS     : 14
```

---

## Use as a Python Library

```python
from secureprobe import run_scanner, CRITICAL, HIGH

findings = run_scanner("https://example.com", deep=True, output="report.html")

critical = [f for f in findings if f.severity == CRITICAL]
for f in critical:
    print(f.module, "|", f.title)
    print("  Fix:", f.remediation)
```

---

## Project Structure

```
secureprobe/
├── secureprobe/
│   ├── __init__.py        # Public API
│   ├── __main__.py        # CLI entry point
│   ├── scanner.py         # 16 scan modules + orchestrator
│   └── reporter.py        # Terminal, text, and HTML output
├── tests/
│   └── test_scanner.py    # Unit tests
├── pyproject.toml         # Build config + pip metadata
├── .gitignore
├── LICENSE
└── README.md
```

---

## Contributing

1. Fork → `git clone` → `pip install -e ".[dev]"`
2. Create a branch: `git checkout -b feature/new-module`
3. Add your module in `scanner.py`, register it in `run_scanner()`
4. Add tests in `tests/`
5. Open a pull request

---

## Legal & Ethics

This tool is built for **defensive security** — to help you find weaknesses in your own systems before attackers do.

- ✅ Scan systems you own or administer
- ✅ Scan systems you have **explicit written authorization** to test
- ❌ Never scan systems without permission
- ❌ Unauthorized port scanning and security testing is illegal in most countries

---

## License

MIT — see [LICENSE](LICENSE)
