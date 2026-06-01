# Changelog

All notable changes to SecureProbe are documented here.

---

## [2.0.0] — 2026-06-02

### Added
- **5 new scan modules** (total: 16)
  - Host Header Injection — forged Host header reflected in body/Location/Link
  - Information Disclosure — error probes for stack traces, SQL errors, PHP warnings, internal IPs, AWS IMDS leakage
  - Clickjacking (dedicated) — verified on HTML responses only
  - Mixed Content — HTTP resources on HTTPS pages
  - Content-Type Validation — missing charset, absent header
- **Active probing upgrades across existing modules**
  - SSL/TLS: actively probes legacy TLS 1.0 / 1.1 support via forced handshake
  - HTTP Methods: PUT write-test with cleanup; TRACE echo verified in response body
  - Rate Limiting: login-endpoint detection + POST brute-force probe
  - CORS: 4 origin variants (subdomain, prefix-spoof, null, arbitrary external)
  - Open Redirect: bypass variants (protocol-relative `//`, auth@ tricks)
  - Sensitive Files: 70+ paths (was 40), including heap dumps, SVN, Mercurial, Spring mappings/beans
  - Information Disclosure: AWS IMDS check, private IP regex scan
  - Cookies: raw Set-Cookie parsing for full attribute visibility; SameSite=None+Secure check; session cookie expiry check
- **Deduplication engine** — `Finding._key` based on module+title hash; `deduplicate()` across all modules keeps highest severity per unique finding
- **`--quiet` / `-q` CLI flag** — summary-only terminal output
- **`--version` / `-v` CLI flag**
- **Modular package structure** — `secureprobe/scanner.py` + `secureprobe/reporter.py` + `secureprobe/__init__.py`
- **`pyproject.toml`** — fully pip-installable; `secureprobe` CLI command registered
- **Unit tests** — `tests/test_scanner.py` covering Finding, dedup, security headers, severity system

### Changed
- Security Headers: added Cache-Control check; HSTS preload advisory; improved CSP analysis (regex-based per-directive rather than plain string search); checks `x-aspnet-version`, `x-aspnetmvc-version`, `x-generator`
- HTML report: redesigned with JetBrains Mono + Inter fonts, conic-gradient score ring, per-grade color
- Version string: `v2.0.0`

### Fixed
- Duplicate findings no longer shown when multiple sub-checks trigger the same issue
- CORS: no longer reports the same ACAO policy multiple times for different probe origins

---

## [1.0.0] — 2026-06-01

- Initial release: 11 modules, text + HTML report, basic CLI
