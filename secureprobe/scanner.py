#!/usr/bin/env python3
"""
SecureProbe v2.0 — Web Security Audit Engine
Core scanner with 16 modules, deduplication, and active probing.

AUTHORIZED USE ONLY — only scan systems you own or have written permission to test.
"""

from __future__ import annotations

import re
import ssl
import sys
import json
import time
import socket
import hashlib
import textwrap
import datetime
import urllib3
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlencode, quote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[!] requests not installed. Run: pip install requests")

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
#  SEVERITY CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS = "CRITICAL","HIGH","MEDIUM","LOW","INFO","PASS"

SEV_COLOR = {
    CRITICAL : Fore.RED    + Style.BRIGHT,
    HIGH     : Fore.RED,
    MEDIUM   : Fore.YELLOW,
    LOW      : Fore.CYAN,
    INFO     : Fore.WHITE  + Style.DIM,
    PASS     : Fore.GREEN,
}
SEV_ORDER  = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4, PASS:5}
SEV_WEIGHT = {CRITICAL:15, HIGH:8, MEDIUM:4, LOW:1, INFO:0, PASS:0}


# ─────────────────────────────────────────────────────────────────────────────
#  FINDING DATA CLASS
# ─────────────────────────────────────────────────────────────────────────────
class Finding:
    __slots__ = ("module","severity","title","description","evidence",
                 "remediation","reference","_key")

    def __init__(self, module: str, severity: str, title: str,
                 description: str = "", evidence: str = "",
                 remediation: str = "", reference: str = ""):
        self.module      = module
        self.severity    = severity
        self.title       = title
        self.description = description
        self.evidence    = evidence or ""
        self.remediation = remediation or ""
        self.reference   = reference or ""
        # Deduplication key — same module + normalised title = same issue
        self._key = hashlib.md5(
            f"{module}::{re.sub(r'[^a-z]+','_', title.lower())}".encode()
        ).hexdigest()[:12]

    def __repr__(self):
        return f"<Finding [{self.severity}] {self.title}>"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def _now_str() -> str:
    return _now().strftime("%Y-%m-%d %H:%M:%S UTC")


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP SESSION
# ─────────────────────────────────────────────────────────────────────────────
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

def build_session(timeout: int = 10) -> tuple:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[500, 502, 503, 504],
                  allowed_methods=["GET","HEAD","OPTIONS","POST"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent"     : CHROME_UA,
        "Accept"         : "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    })
    return session, timeout


def fetch(session, url: str, timeout: int, **kw):
    """GET → (response | None, error | None)"""
    try:
        r = session.get(url, timeout=timeout, verify=False, **kw)
        return r, None
    except Exception as exc:
        return None, str(exc)


def fetch_head(session, url: str, timeout: int, **kw):
    try:
        r = session.head(url, timeout=timeout, verify=False, **kw)
        return r, None
    except Exception as exc:
        return None, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 01 — SECURITY HEADERS  (enhanced)
# ─────────────────────────────────────────────────────────────────────────────
def check_security_headers(resp, base_url: str) -> list[Finding]:
    findings = []
    h = {k.lower(): v.strip() for k, v in resp.headers.items()}
    mod = "Security Headers"

    # ── CSP ──────────────────────────────────────────────────────────────────
    if "content-security-policy" not in h:
        findings.append(Finding(mod, HIGH,
            "Missing Content-Security-Policy",
            "No CSP header. Inline scripts and resources from any origin are "
            "permitted, widening the blast radius of any XSS vulnerability.",
            evidence="Header absent",
            remediation="Content-Security-Policy: default-src 'self'; "
                        "script-src 'self'; object-src 'none'; base-uri 'self'",
            reference="https://owasp.org/www-project-secure-headers/#content-security-policy"
        ))
    else:
        csp = h["content-security-policy"]
        issues = []
        if re.search(r"script-src[^;]*'unsafe-inline'", csp):
            issues.append("'unsafe-inline' in script-src — bypasses XSS protection")
        if re.search(r"script-src[^;]*'unsafe-eval'", csp):
            issues.append("'unsafe-eval' in script-src — allows eval() injection")
        if re.search(r"default-src\s+\*", csp) or re.search(r"script-src\s+\*", csp):
            issues.append("Wildcard (*) source in script-src or default-src")
        if "http://" in csp:
            issues.append("Plaintext HTTP source weakens TLS enforcement")
        if issues:
            findings.append(Finding(mod, MEDIUM,
                "Weak Content-Security-Policy",
                "CSP present but contains insecure directives:\n" +
                "".join(f"  • {i}\n" for i in issues),
                evidence=csp[:200],
                remediation="Use nonces/hashes for inline scripts. "
                            "Remove 'unsafe-inline', 'unsafe-eval', and HTTP sources.",
                reference="https://csp.withgoogle.com/docs/strict-csp.html"))
        else:
            findings.append(Finding(mod, PASS, "Content-Security-Policy configured", csp[:100]))

    # ── X-Frame-Options / frame-ancestors ────────────────────────────────────
    has_xfo = "x-frame-options" in h
    has_fa  = "frame-ancestors" in h.get("content-security-policy", "")
    if not has_xfo and not has_fa:
        findings.append(Finding(mod, MEDIUM,
            "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
            "Page can be embedded in iframes — enables UI redressing / clickjacking.",
            evidence="X-Frame-Options absent; no frame-ancestors in CSP",
            remediation="X-Frame-Options: DENY  —or—  CSP: frame-ancestors 'none'",
            reference="https://owasp.org/www-community/attacks/Clickjacking"))
    elif has_xfo:
        xfo = h.get("x-frame-options","")
        if xfo.upper() not in ("DENY","SAMEORIGIN"):
            findings.append(Finding(mod, LOW,
                "Non-standard X-Frame-Options Value",
                f"Value '{xfo}' is not DENY or SAMEORIGIN.",
                evidence=xfo, remediation="Use DENY or SAMEORIGIN."))
        else:
            findings.append(Finding(mod, PASS, f"X-Frame-Options: {xfo}", ""))

    # ── HSTS ──────────────────────────────────────────────────────────────────
    if base_url.startswith("https"):
        if "strict-transport-security" not in h:
            findings.append(Finding(mod, HIGH,
                "Missing HTTP Strict Transport Security (HSTS)",
                "Browsers will not enforce HTTPS — SSLstrip / protocol-downgrade possible.",
                evidence="Strict-Transport-Security absent",
                remediation="Strict-Transport-Security: max-age=31536000; "
                            "includeSubDomains; preload",
                reference="https://hstspreload.org/"))
        else:
            hsts = h["strict-transport-security"]
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 31536000:
                findings.append(Finding(mod, LOW,
                    f"HSTS max-age Too Short ({age}s < 1 year)",
                    "Short max-age reduces downgrade-attack protection window.",
                    evidence=hsts,
                    remediation="Set max-age=31536000 or higher."))
            else:
                findings.append(Finding(mod, PASS, "HSTS configured", hsts))
            if "preload" not in hsts:
                findings.append(Finding(mod, INFO,
                    "HSTS Preload Directive Missing",
                    "Site is not eligible for browser HSTS preload lists without the "
                    "'preload' directive and includeSubDomains.",
                    evidence=hsts,
                    remediation="Add 'preload' and submit to https://hstspreload.org/"))

    # ── X-Content-Type-Options ────────────────────────────────────────────────
    xcto = h.get("x-content-type-options","")
    if xcto.lower() != "nosniff":
        findings.append(Finding(mod, LOW,
            "Missing X-Content-Type-Options: nosniff",
            "MIME sniffing can cause browsers to execute non-script responses as JS.",
            evidence=f"'{xcto}'" if xcto else "Header absent",
            remediation="X-Content-Type-Options: nosniff"))
    else:
        findings.append(Finding(mod, PASS, "X-Content-Type-Options: nosniff", ""))

    # ── Referrer-Policy ───────────────────────────────────────────────────────
    rp = h.get("referrer-policy","")
    safe_rp = {"no-referrer","no-referrer-when-downgrade","strict-origin",
               "strict-origin-when-cross-origin","same-origin"}
    if not rp:
        findings.append(Finding(mod, LOW, "Missing Referrer-Policy",
            "Full URL (may contain tokens/session IDs) sent in Referer header.",
            evidence="Header absent",
            remediation="Referrer-Policy: strict-origin-when-cross-origin"))
    elif rp.lower() not in safe_rp:
        findings.append(Finding(mod, INFO,
            f"Referrer-Policy Value Review Recommended ({rp})",
            "Permissive Referrer-Policy may leak sensitive URL parameters.",
            evidence=rp,
            remediation="Use strict-origin-when-cross-origin or stricter."))

    # ── Permissions-Policy ────────────────────────────────────────────────────
    if "permissions-policy" not in h and "feature-policy" not in h:
        findings.append(Finding(mod, LOW, "Missing Permissions-Policy",
            "No browser feature policy — camera/mic/geolocation are unrestricted.",
            evidence="Header absent",
            remediation="Permissions-Policy: geolocation=(), microphone=(), camera=()"))

    # ── Server / X-Powered-By version leak ───────────────────────────────────
    for hdr_name in ("server", "x-powered-by", "x-aspnet-version",
                     "x-aspnetmvc-version", "x-generator"):
        val = h.get(hdr_name, "")
        if val:
            if re.search(r"\d+[\.\d]+", val) or hdr_name != "server":
                sev = LOW if "server" in hdr_name else INFO
                findings.append(Finding(mod, sev,
                    f"Version Disclosure via {hdr_name.title()} Header",
                    "Version strings in response headers help attackers pinpoint CVEs.",
                    evidence=f"{hdr_name}: {val}",
                    remediation=f"Remove or mask the {hdr_name.title()} header in server config."))

    # ── Cache-Control on potentially sensitive responses ──────────────────────
    cc = h.get("cache-control","")
    if not cc:
        findings.append(Finding(mod, INFO, "No Cache-Control Header",
            "Without Cache-Control, browsers and proxies may cache sensitive pages.",
            evidence="Header absent",
            remediation="Cache-Control: no-store, no-cache  (on authenticated/sensitive pages)"))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 02 — SSL / TLS  (enhanced: checks old protocol support explicitly)
# ─────────────────────────────────────────────────────────────────────────────
def check_ssl_tls(hostname: str, port: int = 443) -> list[Finding]:
    findings = []
    mod = "SSL/TLS"

    # ── Main handshake (highest-supported protocol) ───────────────────────────
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                cert   = s.getpeercert()
                cipher = s.cipher()          # (name, protocol, bits)
                proto  = s.version()

        # Protocol version
        if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            findings.append(Finding(mod, HIGH,
                f"Deprecated TLS Protocol In Use: {proto}",
                f"Server negotiated {proto} — vulnerable to POODLE/BEAST/downgrade attacks.",
                evidence=f"Negotiated: {proto}",
                remediation="Disable TLS 1.0/1.1. Enforce TLS 1.2 minimum; prefer 1.3.",
                reference="https://www.rfc-editor.org/rfc/rfc8996"))
        else:
            findings.append(Finding(mod, PASS, f"TLS Protocol: {proto}", ""))

        # Cipher strength
        cipher_name  = cipher[0] if cipher else ""
        cipher_bits  = cipher[2] if cipher and len(cipher) > 2 else 0
        weak_patterns = ["RC4","3DES","DES ","NULL","EXPORT","anon","MD5","SHA1"]
        matched = [w for w in weak_patterns if w.upper() in cipher_name.upper()]
        if matched:
            findings.append(Finding(mod, HIGH,
                f"Weak Cipher Suite: {cipher_name}",
                f"Cipher considered cryptographically weak ({', '.join(matched)}).",
                evidence=f"Cipher: {cipher_name}  Bits: {cipher_bits}",
                remediation="Prefer ECDHE+AESGCM / CHACHA20-POLY1305. "
                            "Disable RC4, 3DES, EXPORT, and NULL ciphers.",
                reference="https://wiki.mozilla.org/Security/Server_Side_TLS"))
        elif cipher_bits and cipher_bits < 128:
            findings.append(Finding(mod, MEDIUM,
                f"Short Cipher Key Length ({cipher_bits} bits)",
                "Key length below 128 bits is insufficient for modern security.",
                evidence=f"{cipher_name} — {cipher_bits} bits",
                remediation="Use AES-128 minimum; prefer AES-256 or ChaCha20."))
        else:
            findings.append(Finding(mod, PASS, f"Cipher: {cipher_name}", ""))

        # Certificate expiry & SAN check
        if cert:
            expire_str = cert.get("notAfter","")
            if expire_str:
                try:
                    exp = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=datetime.timezone.utc)
                    days = (exp - _now()).days
                    if days < 0:
                        findings.append(Finding(mod, CRITICAL,
                            "TLS Certificate EXPIRED",
                            f"Certificate expired {abs(days)} days ago.",
                            evidence=f"Expired: {expire_str}",
                            remediation="Renew immediately. Use Let's Encrypt with auto-renewal."))
                    elif days < 14:
                        findings.append(Finding(mod, HIGH,
                            f"Certificate Expires in {days} Days",
                            "Imminent expiry will cause browser trust errors.",
                            evidence=f"Expiry: {expire_str}",
                            remediation="Renew immediately."))
                    elif days < 30:
                        findings.append(Finding(mod, MEDIUM,
                            f"Certificate Expires in {days} Days",
                            "Renewal due soon.", evidence=f"Expiry: {expire_str}",
                            remediation="Schedule renewal now."))
                    else:
                        findings.append(Finding(mod, PASS,
                            f"Certificate valid for {days} days", expire_str))
                except Exception:
                    pass

            # Self-signed / CA check
            subject  = dict(x[0] for x in cert.get("subject",  []))
            issuer   = dict(x[0] for x in cert.get("issuer",   []))
            if subject == issuer:
                findings.append(Finding(mod, HIGH,
                    "Self-Signed Certificate",
                    "Certificate not issued by a trusted CA — browsers show error.",
                    evidence=f"Subject == Issuer: {subject.get('commonName','')}",
                    remediation="Replace with a certificate from a trusted CA "
                                "(e.g., Let's Encrypt, DigiCert)."))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(mod, HIGH,
            "TLS Certificate Validation Failure",
            "Certificate could not be verified (self-signed, wrong hostname, untrusted CA).",
            evidence=str(e),
            remediation="Install a cert from a trusted CA; ensure CN/SAN matches hostname."))
    except ssl.SSLError as e:
        findings.append(Finding(mod, MEDIUM, "TLS Handshake Error", str(e),
            remediation="Review server TLS configuration."))
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        findings.append(Finding(mod, INFO, "Could Not Connect for TLS Check", str(e)))

    # ── Probe for legacy TLS 1.0 / 1.1 support ───────────────────────────────
    for legacy_ver, flag in [("TLSv1", ssl.PROTOCOL_TLS_CLIENT),
                              ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT)]:
        try:
            lctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            lctx.check_hostname = False
            lctx.verify_mode    = ssl.CERT_NONE
            # Force maximum version to old protocol
            ver_map = {"TLSv1": ssl.TLSVersion.TLSv1,
                       "TLSv1.1": ssl.TLSVersion.TLSv1_1}
            if hasattr(ssl, "TLSVersion") and legacy_ver in ver_map:
                lctx.maximum_version = ver_map[legacy_ver]
                lctx.minimum_version = ver_map[legacy_ver]
                with socket.create_connection((hostname, port), timeout=5) as rs:
                    with lctx.wrap_socket(rs, server_hostname=hostname) as ls:
                        neg = ls.version()
                        if neg and legacy_ver in neg:
                            findings.append(Finding(mod, HIGH,
                                f"Server Accepts Legacy {legacy_ver}",
                                f"Server accepted a handshake using {legacy_ver}, "
                                "which is deprecated and insecure.",
                                evidence=f"Negotiated {neg} with forced {legacy_ver} context",
                                remediation=f"Disable {legacy_ver} in server TLS config."))
        except Exception:
            pass   # connection refused / error means not supported — good

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 03 — CORS
# ─────────────────────────────────────────────────────────────────────────────
def check_cors(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "CORS"
    host = urlparse(url).hostname or ""

    test_cases = [
        ("https://evil.example.com",   "Arbitrary external origin"),
        ("null",                        "Null origin (sandbox/file:// bypass)"),
        (f"https://attacker.{host}",   "Subdomain of target"),
        (f"https://{host}.attacker.com","Prefix spoof — target hostname in attacker domain"),
    ]

    seen_issues = set()

    for origin, label in test_cases:
        try:
            r = session.get(url, timeout=timeout, verify=False,
                            headers={"Origin": origin})
            acao = r.headers.get("Access-Control-Allow-Origin","").strip()
            acac = r.headers.get("Access-Control-Allow-Credentials","").strip().lower()
            achd = r.headers.get("Access-Control-Allow-Headers","")
            acm  = r.headers.get("Access-Control-Allow-Methods","")

            if not acao:
                continue

            key = f"{acao}::{acac}"
            if key in seen_issues:
                continue

            if acao == "*" and acac == "true":
                seen_issues.add(key)
                findings.append(Finding(mod, CRITICAL,
                    "CORS: Wildcard Origin + Credentials",
                    "Wildcard ACAO with Allow-Credentials:true is invalid per spec "
                    "but some servers send it — attackers can exfiltrate authenticated data.",
                    evidence=f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                    remediation="Never combine wildcard ACAO with credentials. "
                                "Allowlist specific origins server-side.",
                    reference="https://portswigger.net/web-security/cors"))

            elif (acao == origin or acao == "*") and acac == "true":
                seen_issues.add(key)
                findings.append(Finding(mod, HIGH,
                    f"CORS: Arbitrary Origin Reflected with Credentials ({label})",
                    "Server reflects attacker origin and permits credentials — "
                    "an attacker page can make authenticated requests and read responses.",
                    evidence=f"Sent: {origin}  Reflected: {acao}  Creds: {acac}",
                    remediation="Validate Origin strictly against a server-side allowlist.",
                    reference="https://portswigger.net/web-security/cors"))

            elif acao == "*":
                seen_issues.add(key)
                findings.append(Finding(mod, LOW,
                    "CORS: Wildcard Origin (No Credentials)",
                    "Any site can read non-credentialed responses. "
                    "Acceptable for public APIs only.",
                    evidence=f"ACAO: {acao}",
                    remediation="Restrict ACAO to known trusted origins if endpoint "
                                "returns non-public data."))

            elif acao == origin and origin != "null":
                seen_issues.add(key)
                findings.append(Finding(mod, MEDIUM,
                    f"CORS: Origin Reflected Without Validation ({label})",
                    "Server echoes the Origin header without apparent validation. "
                    "Combined with sensitive responses this can leak data.",
                    evidence=f"Sent: {origin}  Returned ACAO: {acao}",
                    remediation="Validate Origin against an explicit allowlist."))

        except Exception:
            pass

    if not findings:
        findings.append(Finding(mod, PASS, "CORS policy appears correctly restricted", ""))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 04 — COOKIE SECURITY
# ─────────────────────────────────────────────────────────────────────────────
def check_cookies(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Cookie Security"

    try:
        r = session.get(url, timeout=timeout, verify=False)
    except Exception as e:
        findings.append(Finding(mod, INFO, "Cookie fetch failed", str(e)))
        return findings

    # Parse raw Set-Cookie headers for full attribute visibility
    raw_cookies = r.headers.get_all("Set-Cookie") if hasattr(r.headers, "get_all") \
        else [v for k,v in r.headers.items() if k.lower() == "set-cookie"]

    if not raw_cookies:
        findings.append(Finding(mod, INFO, "No Set-Cookie headers in response", ""))
        return findings

    is_https = url.startswith("https")
    seen = set()

    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name  = parts[0].split("=")[0].strip() if parts else "unknown"

        if name in seen:
            continue
        seen.add(name)

        attrs_lower = " ".join(parts[1:]).lower()

        # Sensitive session cookie names
        session_names = {"sessionid","session","sess","phpsessid","jsessionid",
                         "auth","token","access_token","refresh_token","remember_me"}
        is_session = any(sn in name.lower() for sn in session_names)

        if "httponly" not in attrs_lower:
            sev = HIGH if is_session else MEDIUM
            findings.append(Finding(mod, sev,
                f"Cookie '{name}' Missing HttpOnly",
                "Without HttpOnly, JavaScript can read this cookie — "
                "an XSS vulnerability enables theft.",
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Add HttpOnly to '{name}'."))

        if is_https and "secure" not in attrs_lower:
            sev = HIGH if is_session else MEDIUM
            findings.append(Finding(mod, sev,
                f"Cookie '{name}' Missing Secure Flag",
                "Cookie can be transmitted over plain HTTP on HTTPS sites "
                "if a protocol downgrade occurs.",
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Add Secure flag to '{name}'."))

        if "samesite" not in attrs_lower:
            findings.append(Finding(mod, LOW,
                f"Cookie '{name}' Missing SameSite",
                "Without SameSite the cookie is sent on cross-site requests "
                "— older browsers are susceptible to CSRF.",
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Add SameSite=Strict or SameSite=Lax to '{name}'."))
        elif "samesite=none" in attrs_lower and "secure" not in attrs_lower:
            findings.append(Finding(mod, MEDIUM,
                f"Cookie '{name}' SameSite=None Without Secure",
                "SameSite=None requires the Secure attribute — "
                "browsers will reject or downgrade this cookie.",
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation=f"Add Secure flag alongside SameSite=None."))

        # Check for overly long expiry on session cookies
        if is_session and "max-age" in attrs_lower:
            m = re.search(r"max-age\s*=\s*(\d+)", attrs_lower)
            if m and int(m.group(1)) > 86400 * 30:
                findings.append(Finding(mod, LOW,
                    f"Session Cookie '{name}' Has Long Expiry",
                    f"max-age > 30 days on a session cookie increases window for theft.",
                    evidence=f"max-age={m.group(1)}",
                    remediation="Reduce session cookie max-age to ≤24 hours."))

        if not any(f.title.endswith(f"'{name}'") for f in findings):
            findings.append(Finding(mod, PASS, f"Cookie '{name}' flags OK", ""))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 05 — SENSITIVE FILE / PATH EXPOSURE  (50+ paths)
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Version control
    ("/.git/HEAD",               HIGH,   "Git HEAD exposed — source code recoverable"),
    ("/.git/config",             HIGH,   "Git config exposed — reveals remotes/auth"),
    ("/.git/COMMIT_EDITMSG",     HIGH,   "Git commit message exposed"),
    ("/.svn/entries",            HIGH,   "SVN repository metadata exposed"),
    ("/.hg/hgrc",                HIGH,   "Mercurial config exposed"),
    # Environment / secrets
    ("/.env",                    CRITICAL,"Dotenv file — likely contains credentials"),
    ("/.env.local",              CRITICAL,"Local env file exposed"),
    ("/.env.production",         CRITICAL,"Production env file exposed"),
    ("/.env.backup",             CRITICAL,"Env backup exposed"),
    ("/.env.example",            MEDIUM,  "Env example — reveals var names"),
    # Config files
    ("/config.php",              HIGH,   "PHP config exposed"),
    ("/config.php.bak",          HIGH,   "PHP config backup exposed"),
    ("/wp-config.php",           CRITICAL,"WordPress config — DB credentials"),
    ("/wp-config.php.bak",       CRITICAL,"WordPress config backup"),
    ("/config/database.yml",     HIGH,   "Rails DB config — credentials"),
    ("/config/secrets.yml",      CRITICAL,"Rails secrets file"),
    ("/web.config",              HIGH,   "ASP.NET web.config exposed"),
    ("/appsettings.json",        HIGH,   "ASP.NET appsettings — may contain DB strings"),
    ("/application.properties",  HIGH,   "Spring Boot properties — may have secrets"),
    ("/application.yml",         HIGH,   "Spring Boot YAML config"),
    # Database dumps
    ("/database.sql",            CRITICAL,"SQL dump exposed"),
    ("/backup.sql",              CRITICAL,"SQL backup exposed"),
    ("/dump.sql",                CRITICAL,"SQL dump exposed"),
    ("/db.sql",                  CRITICAL,"DB SQL file exposed"),
    # Backups / archives
    ("/backup.zip",              HIGH,   "Backup archive exposed"),
    ("/backup.tar.gz",           HIGH,   "Backup tarball exposed"),
    ("/site.zip",                HIGH,   "Site archive exposed"),
    # PHP / server info
    ("/phpinfo.php",             HIGH,   "phpinfo() — full server config exposed"),
    ("/info.php",                HIGH,   "phpinfo() variant"),
    ("/test.php",                MEDIUM, "Test PHP file"),
    ("/php.php",                 MEDIUM, "PHP test file"),
    ("/server-status",           MEDIUM, "Apache server-status exposed"),
    ("/server-info",             MEDIUM, "Apache server-info exposed"),
    # Access control files
    ("/.htpasswd",               CRITICAL,"Hashed credentials exposed"),
    ("/.htaccess",               MEDIUM,  ".htaccess reveals server rules"),
    # Development leftovers
    ("/package.json",            LOW,    "Node.js package.json exposed"),
    ("/package-lock.json",       LOW,    "Node.js lock file — dependency fingerprint"),
    ("/composer.json",           LOW,    "PHP Composer config"),
    ("/composer.lock",           LOW,    "PHP Composer lock — exact versions"),
    ("/Gemfile",                 LOW,    "Ruby Gemfile exposed"),
    ("/requirements.txt",        LOW,    "Python requirements exposed"),
    ("/Dockerfile",              MEDIUM, "Dockerfile exposed — reveals build process"),
    ("/docker-compose.yml",      MEDIUM, "docker-compose exposed — service topology"),
    ("/docker-compose.yaml",     MEDIUM, "docker-compose exposed"),
    # API docs
    ("/swagger.json",            MEDIUM, "Swagger spec — full API map"),
    ("/swagger.yaml",            MEDIUM, "Swagger YAML spec"),
    ("/openapi.json",            MEDIUM, "OpenAPI spec"),
    ("/openapi.yaml",            MEDIUM, "OpenAPI YAML spec"),
    ("/api-docs",                MEDIUM, "API documentation exposed"),
    ("/api/swagger.json",        MEDIUM, "API Swagger spec"),
    ("/v1/swagger.json",         MEDIUM, "Versioned Swagger spec"),
    ("/v2/api-docs",             MEDIUM, "Spring Swagger v2 docs"),
    # Spring Boot actuators
    ("/actuator",                HIGH,   "Spring Boot actuator root — app control"),
    ("/actuator/env",            CRITICAL,"Spring Boot env — exposes all config vars"),
    ("/actuator/health",         INFO,   "Spring Boot health endpoint"),
    ("/actuator/info",           LOW,    "Spring Boot info endpoint"),
    ("/actuator/mappings",       MEDIUM, "Spring Boot mappings — full route list"),
    ("/actuator/beans",          MEDIUM, "Spring Boot beans endpoint"),
    ("/actuator/heapdump",       CRITICAL,"Heap dump — may contain secrets in memory"),
    ("/actuator/threaddump",     LOW,    "Thread dump endpoint"),
    # Admin / management panels
    ("/admin",                   MEDIUM, "Admin panel accessible"),
    ("/admin/",                  MEDIUM, "Admin panel accessible"),
    ("/phpmyadmin",              HIGH,   "phpMyAdmin DB management UI"),
    ("/phpmyadmin/",             HIGH,   "phpMyAdmin DB management UI"),
    ("/adminer.php",             HIGH,   "Adminer DB tool exposed"),
    ("/wp-admin",                MEDIUM, "WordPress admin panel"),
    ("/wp-login.php",            LOW,    "WordPress login page"),
    ("/administrator",           MEDIUM, "CMS admin panel"),
    # Logs
    ("/logs/",                   HIGH,   "Logs directory accessible"),
    ("/log/",                    HIGH,   "Log directory accessible"),
    ("/debug.log",               HIGH,   "Debug log file exposed"),
    ("/error.log",               HIGH,   "Error log exposed"),
    ("/access.log",              HIGH,   "Access log exposed"),
    # Misc
    ("/robots.txt",              INFO,   "robots.txt — may reveal sensitive paths"),
    ("/sitemap.xml",             INFO,   "Sitemap — exposes URL structure"),
    ("/crossdomain.xml",         LOW,    "Flash cross-domain policy"),
    ("/security.txt",            INFO,   "Security.txt (positive if disclosure program)"),
    ("/.well-known/security.txt",INFO,   "Security.txt (positive if disclosure program)"),
]

SECRET_KW = ["password","passwd","secret","api_key","apikey","access_key",
             "private_key","token","db_pass","database_url","auth_token",
             "aws_secret","sendgrid","stripe","twilio","mailgun"]

def check_sensitive_files(session, url: str, timeout: int,
                           deep: bool = False) -> list[Finding]:
    findings = []
    mod = "Sensitive File Exposure"
    base = url.rstrip("/")
    seen_titles = set()

    paths = SENSITIVE_PATHS if deep else SENSITIVE_PATHS[:40]

    for path, default_sev, description in paths:
        try:
            r = session.get(base + path, timeout=timeout, verify=False,
                            allow_redirects=False)
            if r.status_code not in (200, 206, 403):
                continue

            title = f"Accessible: {path}"
            if title in seen_titles:
                continue
            seen_titles.add(title)

            if r.status_code == 403:
                findings.append(Finding(mod, INFO,
                    f"Path Exists (403 Forbidden): {path}",
                    f"{description} — returns 403, resource exists but is blocked.",
                    evidence="HTTP 403",
                    remediation="Verify ACL; consider removing file from server."))
                continue

            # Escalate severity based on actual content
            body_lower = r.text[:2000].lower()
            sev = default_sev
            if any(kw in body_lower for kw in SECRET_KW):
                sev = CRITICAL
            elif default_sev == INFO and any(kw in path for kw in
                [".git","actuator",".env","wp-config",".htpasswd"]):
                sev = HIGH

            snippet = r.text[:150].strip().replace("\n"," ")[:120]
            findings.append(Finding(mod, sev,
                f"Exposed: {path}",
                description,
                evidence=f"HTTP {r.status_code} — {snippet}",
                remediation=f"Remove {path} from the web root or restrict via ACL.",
                reference="https://owasp.org/www-project-web-security-testing-guide/"))
        except Exception:
            pass

    if not any(f.severity not in (PASS, INFO) for f in findings):
        checked = len(paths)
        findings.append(Finding(mod, PASS,
            f"No sensitive files found ({checked} paths checked)", ""))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 06 — HTTP METHODS
# ─────────────────────────────────────────────────────────────────────────────
def check_http_methods(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "HTTP Methods"

    dangerous = {"PUT","DELETE","TRACE","TRACK","CONNECT",
                 "PROPFIND","PROPPATCH","MKCOL","MOVE","COPY","LOCK","UNLOCK"}

    # Enumerate via OPTIONS
    advertised = set()
    try:
        r = session.options(url, timeout=timeout, verify=False)
        allow = r.headers.get("Allow","") + "," + \
                r.headers.get("Access-Control-Allow-Methods","")
        advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
    except Exception:
        pass

    # Actively probe TRACE
    try:
        r = session.request("TRACE", url, timeout=timeout, verify=False)
        if r.status_code == 200 and "TRACE" in (r.text or "")[:200].upper():
            findings.append(Finding(mod, MEDIUM,
                "HTTP TRACE Method Enabled (Verified)",
                "TRACE echoes the request — Cross-Site Tracing (XST) can steal "
                "HttpOnly cookies via XMLHTTP in some browser configurations.",
                evidence=f"TRACE returned 200 with request echo",
                remediation="Disable TRACE in web server config.",
                reference="https://owasp.org/www-community/attacks/Cross_Site_Tracing"))
        advertised.discard("TRACE")   # already reported if active
    except Exception:
        pass

    # Probe PUT with a harmless path (just check status, don't write)
    try:
        probe_url = url.rstrip("/") + "/secureprobe-writetest.txt"
        r = session.request("PUT", probe_url, timeout=timeout, verify=False,
                            data=b"secureprobe-test", allow_redirects=False)
        if r.status_code in (200, 201, 204):
            findings.append(Finding(mod, CRITICAL,
                "HTTP PUT Method Enabled — Arbitrary File Write",
                "Server accepted a PUT request — an attacker may upload "
                "arbitrary files (webshells, malware) to the server.",
                evidence=f"PUT {probe_url} → HTTP {r.status_code}",
                remediation="Disable HTTP PUT unless required for a specific endpoint, "
                            "and require authentication for all write methods."))
        # Cleanup attempt
        try:
            session.request("DELETE", probe_url, timeout=4, verify=False)
        except Exception:
            pass
    except Exception:
        pass

    # Report risky advertised methods
    risky_adv = advertised & dangerous
    if risky_adv:
        findings.append(Finding(mod, MEDIUM,
            f"Dangerous Methods Advertised: {', '.join(sorted(risky_adv))}",
            "Server advertises methods that could enable file manipulation "
            "or information leakage.",
            evidence=f"Allow/ACAM header: {', '.join(sorted(advertised))}",
            remediation="Restrict to GET, POST, HEAD unless WebDAV/REST explicitly needed."))

    if not findings:
        adv_str = ', '.join(sorted(advertised)) if advertised else "none"
        findings.append(Finding(mod, PASS,
            "HTTP methods appear appropriately restricted",
            f"Advertised: {adv_str}"))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 07 — OPEN REDIRECT
# ─────────────────────────────────────────────────────────────────────────────
def check_open_redirect(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Open Redirect"
    base = url.rstrip("/")
    marker = "evil-openredirect-probe.example.com"

    params = ["next","url","redirect","return","goto","redir","destination",
              "to","redirect_uri","returnUrl","forward","link","continue",
              "target","back","location","return_url","callback","service"]

    bypasses = [
        f"https://{marker}",
        f"//{marker}",                    # protocol-relative
        f"https://{marker}%2f@{marker}",  # auth@ bypass
        f"https://trusted.com@{marker}",  # auth@ variation
    ]

    found = False
    for param in params:
        if found:
            break
        for bypass in bypasses[:2]:   # keep request count reasonable
            try:
                test_url = f"{base}?{param}={quote(bypass, safe=':/@')}"
                r = session.get(test_url, timeout=timeout, verify=False,
                                allow_redirects=False)
                if r.status_code in (301,302,303,307,308):
                    loc = r.headers.get("Location","")
                    if marker in loc or loc.lstrip("/").startswith("/") is False:
                        findings.append(Finding(mod, MEDIUM,
                            f"Open Redirect via ?{param}=",
                            "Parameter accepts arbitrary external URLs — "
                            "phishing / credential harvesting via trusted domain link.",
                            evidence=f"?{param}={bypass}\n→ Location: {loc}",
                            remediation="Validate redirect targets against a strict "
                                        "server-side allowlist. Reject external URLs.",
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/"
                                      "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"))
                        found = True
                        break
            except Exception:
                pass

    if not findings:
        findings.append(Finding(mod, PASS,
            "No open redirect detected on common parameters", ""))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 08 — DIRECTORY LISTING
# ─────────────────────────────────────────────────────────────────────────────
def check_directory_listing(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Directory Listing"

    paths = ["/images/","/uploads/","/files/","/assets/","/static/",
             "/css/","/js/","/backup/","/temp/","/tmp/","/logs/",
             "/media/","/public/","/data/","/docs/"]
    indicators = ["index of /","directory listing","parent directory",
                  "<title>index of","[to parent directory]","apache/","nginx/"]

    base = url.rstrip("/")
    triggered = []
    for p in paths:
        try:
            r = session.get(base + p, timeout=timeout, verify=False)
            body = r.text[:3000].lower()
            if r.status_code == 200 and any(ind in body for ind in indicators):
                triggered.append(p)
        except Exception:
            pass

    if triggered:
        findings.append(Finding(mod, MEDIUM,
            f"Directory Listing Enabled ({len(triggered)} path(s))",
            "Web server returns file listings — exposes internal structure and files.",
            evidence="Listing found at: " + ", ".join(triggered),
            remediation="Apache: Options -Indexes  |  Nginx: autoindex off;  "
                        "|  IIS: Disable Directory Browsing",
            reference="https://owasp.org/www-community/vulnerabilities/"
                      "Unprotected_Directory_Browsing"))
    else:
        findings.append(Finding(mod, PASS,
            "No directory listing detected", f"Tested {len(paths)} paths"))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 09 — REDIRECT CHAIN
# ─────────────────────────────────────────────────────────────────────────────
def check_redirect_chain(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Redirect Chain"

    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        chain = r.history

        if url.startswith("http://"):
            if not r.url.startswith("https://"):
                findings.append(Finding(mod, HIGH,
                    "No HTTPS Upgrade Redirect",
                    "HTTP requests are not redirected to HTTPS.",
                    evidence=f"Final URL: {r.url}",
                    remediation="Add 301 redirect from http:// to https://"))
            else:
                findings.append(Finding(mod, PASS,
                    "HTTP correctly redirects to HTTPS", f"→ {r.url}"))

        if len(chain) > 3:
            steps = " → ".join(h.url for h in chain) + " → " + r.url
            findings.append(Finding(mod, LOW,
                f"Long Redirect Chain ({len(chain)} hops)",
                "Excess redirects add latency and complicate caching.",
                evidence=steps[:300],
                remediation="Consolidate to a single redirect hop."))

        # Mixed-content in chain
        if r.url.startswith("https://"):
            http_hops = [h.url for h in chain if h.url.startswith("http://")]
            if http_hops:
                findings.append(Finding(mod, MEDIUM,
                    "HTTP Hop in HTTPS Redirect Chain",
                    "Chain passes through an unencrypted URL — cookies sent in the "
                    "clear during that hop.",
                    evidence=str(http_hops[:3]),
                    remediation="Ensure all redirect hops use HTTPS."))

    except Exception as e:
        findings.append(Finding(mod, INFO, "Redirect chain check error", str(e)))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 10 — RATE LIMITING
# ─────────────────────────────────────────────────────────────────────────────
def check_rate_limiting(session, url: str, timeout: int) -> list[Finding]:
    mod = "Rate Limiting"

    # Check login / auth endpoint first (most critical)
    login_paths = ["/login","/api/login","/auth/login","/signin",
                   "/api/auth","/user/login","/account/login"]
    base = url.rstrip("/")

    def probe_endpoint(endpoint: str, n: int = 20) -> dict:
        statuses = []
        throttle_headers = []
        for _ in range(n):
            try:
                r = session.post(endpoint, timeout=timeout, verify=False,
                                 data={"username":"probe","password":"probe"},
                                 allow_redirects=False)
                statuses.append(r.status_code)
                for h in ("Retry-After","X-RateLimit-Limit","RateLimit-Limit",
                          "X-RateLimit-Remaining"):
                    if r.headers.get(h):
                        throttle_headers.append(h)
                if r.status_code == 429:
                    return {"throttled": True, "headers": throttle_headers,
                            "endpoint": endpoint, "status": 429}
            except Exception:
                break
        return {"throttled": bool(throttle_headers),
                "headers": list(set(throttle_headers)),
                "endpoint": endpoint, "status": statuses[-1] if statuses else 0}

    findings = []

    # Probe login endpoints
    login_probed = False
    for lp in login_paths:
        ep = base + lp
        try:
            head, _ = fetch_head(session, ep, 4)
            if head and head.status_code not in (404, 410):
                result = probe_endpoint(ep)
                login_probed = True
                if not result["throttled"]:
                    findings.append(Finding(mod, HIGH,
                        f"No Rate Limiting on Login Endpoint: {lp}",
                        f"20 rapid POST requests to {lp} completed without throttling "
                        "— endpoint is vulnerable to credential brute-force.",
                        evidence=f"No 429 or rate-limit headers observed at {ep}",
                        remediation="Apply rate limiting (≤5 req/min per IP) and "
                                    "account lockout after failed attempts.",
                        reference="https://owasp.org/www-community/controls/"
                                  "Blocking_Brute_Force_Attacks"))
                else:
                    findings.append(Finding(mod, PASS,
                        f"Rate limiting detected on {lp}",
                        f"Headers: {result['headers']}"))
                break
        except Exception:
            pass

    # Probe main URL
    throttled_main = False
    for i in range(20):
        try:
            r = session.get(url, timeout=timeout, verify=False)
            for h in ("X-RateLimit-Limit","RateLimit-Limit","Retry-After"):
                if r.headers.get(h):
                    throttled_main = True
            if r.status_code == 429:
                throttled_main = True
                break
        except Exception:
            break

    if not throttled_main and not login_probed:
        findings.append(Finding(mod, MEDIUM,
            "No Rate Limiting Detected on Main URL",
            "20 rapid requests completed with no throttling response.",
            evidence="No 429, Retry-After, or X-RateLimit-* headers",
            remediation="Implement rate limiting on all endpoints. "
                        "Return 429 with Retry-After header."))
    elif throttled_main:
        findings.append(Finding(mod, PASS,
            "Rate limiting present on main URL", ""))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 11 — SUBRESOURCE INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────
def check_subresource_integrity(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Subresource Integrity"

    try:
        r = session.get(url, timeout=timeout, verify=False)
    except Exception:
        return findings

    host = urlparse(url).hostname
    script_re = re.compile(r'<script[^>]+src=["\']?(https?://[^\s"\'><]+)["\']?[^>]*>', re.I)
    link_re   = re.compile(r'<link[^>]+href=["\']?(https?://[^\s"\'><]+\.css[^\s"\'><]*)["\']?[^>]*>', re.I)

    missing = []
    for pat in (script_re, link_re):
        for m in pat.finditer(r.text):
            tag   = m.group(0)
            src   = m.group(1)
            thost = urlparse(src).hostname
            if thost and thost != host and "integrity=" not in tag.lower():
                missing.append(src[:80])

    # Deduplicate
    missing = list(dict.fromkeys(missing))

    if missing:
        resources = "\n".join(f"  {u}" for u in missing[:8])
        findings.append(Finding(mod, MEDIUM,
            f"Missing SRI on {len(missing)} External Resource(s)",
            "External scripts/stylesheets without SRI hashes can be tampered "
            "with by a compromised CDN to inject malicious code.",
            evidence=resources,
            remediation='Add integrity="sha384-..." crossorigin="anonymous" '
                        "to external <script> and <link> tags.",
            reference="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"))
    else:
        findings.append(Finding(mod, PASS,
            "SRI in use or no external resources found", ""))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 12 — INFORMATION DISCLOSURE (response body / errors)
# ─────────────────────────────────────────────────────────────────────────────
def check_info_disclosure(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Information Disclosure"

    # Stack trace / debug triggers
    error_probes = [
        ("/?id='",             "SQL quote injection"),
        ("/?id=1/0",           "Division by zero"),
        ("/error/404nonexist", "Nonexistent path"),
        ("/<script>",          "XSS in path"),
    ]

    stack_patterns = [
        (r"(?:exception|traceback|stack trace)",      MEDIUM, "Stack Trace in Response"),
        (r"(?:mysql_|mysqli_|pg_|oci_)\w+\(",         HIGH,   "Database Function Name Leaked"),
        (r"sql\s+(?:error|syntax|state)",             HIGH,   "SQL Error Message Exposed"),
        (r"(?:warning|notice|fatal error):\s+\w+",   MEDIUM, "PHP Error in Response"),
        (r"at\s+\w[\w\.]+\([\w\.]+:\d+\)",           MEDIUM, "Java Stack Frame Exposed"),
        (r"<b>(?:Fatal error|Parse error|Warning)</b>",MEDIUM,"PHP Error Tag in HTML"),
        (r"ORA-\d{5}:",                               HIGH,   "Oracle Database Error Code"),
        (r"Microsoft OLE DB Provider",                HIGH,   "MSSQL OLE DB Error"),
        (r"SQLSTATE\[\w+\]",                          HIGH,   "SQLSTATE Error Exposed"),
        (r"<pre>.*?(?:Warning|Error).*?</pre>",       MEDIUM, "Debug Block in Response"),
    ]

    base = url.rstrip("/")
    seen_issues = set()

    for path, label in error_probes:
        try:
            r = session.get(base + path, timeout=timeout, verify=False)
            body = r.text[:5000]
            body_lower = body.lower()

            for pattern, sev, title in stack_patterns:
                if title in seen_issues:
                    continue
                m = re.search(pattern, body_lower if sev != HIGH else body,
                              re.IGNORECASE | re.DOTALL)
                if m:
                    seen_issues.add(title)
                    snippet = body[max(0,m.start()-30):m.start()+120].strip()
                    findings.append(Finding(mod, sev, title,
                        f"Triggered via {label} probe: server returned diagnostic "
                        "information that helps attackers understand internals.",
                        evidence=f"Path: {path}\nMatch: {snippet[:200]}",
                        remediation="Disable debug mode in production. "
                                    "Return generic error pages. "
                                    "Log errors server-side only.",
                        reference="https://owasp.org/www-project-web-security-testing-guide/"
                                  "v42/4-Web_Application_Security_Testing/"
                                  "08-Testing_for_Error_Handling/"))
        except Exception:
            pass

    # Check for internal IP / private data in main response
    try:
        r = session.get(url, timeout=timeout, verify=False)
        body = r.text[:10000]
        private_ip_re = re.compile(
            r"\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
            r"|192\.168\.\d+\.\d+|127\.0\.0\.\d+)\b")
        ips = list(dict.fromkeys(private_ip_re.findall(body)))
        if ips:
            findings.append(Finding(mod, MEDIUM,
                "Internal IP Address(es) Leaked in Response",
                "Private network addresses appear in the response, "
                "revealing internal network topology.",
                evidence=", ".join(ips[:5]),
                remediation="Strip internal IP references from application output "
                            "and proxy/load balancer headers."))

        # AWS metadata URL leakage
        if "169.254.169.254" in body:
            findings.append(Finding(mod, HIGH,
                "AWS Metadata IP (169.254.169.254) in Response",
                "AWS IMDS address found in response — possible SSRF vector or "
                "misconfigured internal request being echoed.",
                evidence="169.254.169.254 found in body",
                remediation="Audit code for SSRF vectors. Block IMDS access "
                            "from application layer using IMDSv2."))
    except Exception:
        pass

    if not findings:
        findings.append(Finding(mod, PASS,
            "No obvious information disclosure detected", ""))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 13 — CLICKJACKING (active frame test)
# ─────────────────────────────────────────────────────────────────────────────
def check_clickjacking(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Clickjacking"

    try:
        r = session.get(url, timeout=timeout, verify=False)
        h = {k.lower(): v for k, v in r.headers.items()}
        xfo = h.get("x-frame-options","")
        csp = h.get("content-security-policy","")
        has_fa = "frame-ancestors" in csp

        if not xfo and not has_fa:
            # Confirm it's actually frameable (is HTML?)
            ct = h.get("content-type","")
            if "html" in ct:
                findings.append(Finding(mod, MEDIUM,
                    "Page is Likely Frameable (Clickjacking Risk)",
                    "No X-Frame-Options or CSP frame-ancestors found on an HTML page. "
                    "Attacker can embed this page in a transparent iframe and trick "
                    "users into clicking invisible buttons (UI redressing).",
                    evidence="X-Frame-Options: absent  |  CSP frame-ancestors: absent",
                    remediation="Add X-Frame-Options: DENY  or  "
                                "Content-Security-Policy: frame-ancestors 'none'",
                    reference="https://owasp.org/www-community/attacks/Clickjacking"))
        else:
            val = xfo or f"CSP frame-ancestors: {csp[csp.find('frame-ancestors'):csp.find('frame-ancestors')+40]}"
            findings.append(Finding(mod, PASS, "Clickjacking protection present", val[:80]))
    except Exception as e:
        findings.append(Finding(mod, INFO, "Clickjacking check error", str(e)))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 14 — HOST HEADER INJECTION
# ─────────────────────────────────────────────────────────────────────────────
def check_host_header_injection(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Host Header Injection"
    poison_host = "evil-probe.secureprobe.test"

    try:
        r = session.get(url, timeout=timeout, verify=False,
                        headers={"Host": poison_host})
        body = r.text[:3000]
        hdrs = {k.lower():v for k,v in r.headers.items()}

        reflected_in_body    = poison_host in body
        reflected_in_loc     = poison_host in hdrs.get("location","")
        reflected_in_link    = poison_host in hdrs.get("link","")

        if reflected_in_body or reflected_in_loc or reflected_in_link:
            where = []
            if reflected_in_body: where.append("response body")
            if reflected_in_loc:  where.append("Location header")
            if reflected_in_link: where.append("Link header")
            findings.append(Finding(mod, HIGH,
                "Host Header Injection — Poisoned Host Reflected",
                f"Server reflected a forged Host header in: {', '.join(where)}. "
                "Can enable password-reset poisoning, cache poisoning, and SSRF.",
                evidence=f"Sent Host: {poison_host}  |  Reflected in: {', '.join(where)}",
                remediation="Validate the Host header against an explicit allowlist "
                            "of known domain names. Never use the Host header for "
                            "link generation without validation.",
                reference="https://portswigger.net/web-security/host-header"))
        else:
            findings.append(Finding(mod, PASS,
                "Host header not reflected in response", ""))
    except Exception as e:
        findings.append(Finding(mod, INFO, "Host header check error", str(e)))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 15 — MIXED CONTENT
# ─────────────────────────────────────────────────────────────────────────────
def check_mixed_content(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Mixed Content"

    if not url.startswith("https"):
        return findings

    try:
        r = session.get(url, timeout=timeout, verify=False)
        body = r.text[:50000]

        http_resources = re.findall(
            r'(?:src|href|action|data)=["\']http://[^"\'<>]+["\']',
            body, re.I)
        # Deduplicate
        http_resources = list(dict.fromkeys(http_resources))[:10]

        if http_resources:
            findings.append(Finding(mod, MEDIUM,
                f"Mixed Content: {len(http_resources)} HTTP Resource(s) on HTTPS Page",
                "HTTPS page loads resources over HTTP — browsers block active "
                "mixed content (scripts/iframes) and may warn for passive content.",
                evidence="\n".join(http_resources[:5]),
                remediation="Change all resource URLs to HTTPS or protocol-relative (//)."))
        else:
            findings.append(Finding(mod, PASS,
                "No obvious mixed content found", ""))
    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 16 — CONTENT-TYPE VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
def check_content_type(session, url: str, timeout: int) -> list[Finding]:
    findings = []
    mod = "Content-Type"

    try:
        r = session.get(url, timeout=timeout, verify=False)
        ct = r.headers.get("Content-Type","")

        if not ct:
            findings.append(Finding(mod, LOW,
                "Missing Content-Type Header",
                "Absent Content-Type lets browsers MIME-sniff the response type.",
                evidence="Header absent",
                remediation="Set a Content-Type header on all responses."))
        elif "html" in ct.lower() and "charset" not in ct.lower():
            findings.append(Finding(mod, LOW,
                "Content-Type Missing Charset",
                "HTML responses without charset declaration may be vulnerable to "
                "UTF-7 / character set sniffing attacks in older browsers.",
                evidence=ct,
                remediation="Add; charset=utf-8 to Content-Type header."))
        else:
            findings.append(Finding(mod, PASS, f"Content-Type: {ct[:60]}", ""))
    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────
def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove exact-key duplicates; keep highest severity per key."""
    best: dict[str, Finding] = {}
    for f in findings:
        k = f._key
        if k not in best or SEV_ORDER[f.severity] < SEV_ORDER[best[k].severity]:
            best[k] = f
    return list(best.values())


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────
def run_scanner(target: str, deep: bool = False, output: str | None = None,
                quiet: bool = False) -> list[Finding]:
    from .reporter import print_banner, print_finding, generate_text_report, \
                          generate_html_report

    print_banner()

    if not target.startswith(("http://","https://")):
        target = "https://" + target
    target  = target.rstrip("/")
    parsed  = urlparse(target)
    host    = parsed.hostname or ""
    port    = parsed.port or (443 if target.startswith("https") else 80)

    print(f"{Fore.CYAN}[*] Target  : {Style.BRIGHT}{target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Host    : {host}:{port}")
    print(f"{Fore.CYAN}[*] Mode    : {'Deep' if deep else 'Standard'}")
    print(f"{Fore.CYAN}[*] Started : {_now_str()}")
    print()

    session, timeout = build_session(timeout=14 if deep else 9)
    all_findings: list[Finding] = []
    t0 = time.monotonic()

    # Initial connection
    print(f"{Fore.MAGENTA}[~] Connecting...{Style.RESET_ALL}")
    resp, err = fetch(session, target, timeout)
    if resp is None:
        print(f"{Fore.RED}[!] Cannot reach target: {err}{Style.RESET_ALL}")
        return []

    print(f"    HTTP {resp.status_code}  |  "
          f"Server: {resp.headers.get('Server','?')[:30]}  |  "
          f"Content-Type: {resp.headers.get('Content-Type','?')[:40]}")
    print()

    modules = [
        ("Security Headers",         lambda: check_security_headers(resp, target)),
        ("SSL/TLS Configuration",    lambda: check_ssl_tls(host, port)
                                              if target.startswith("https")
                                              else [Finding("SSL/TLS", HIGH,
                                                    "Site Not Served Over HTTPS",
                                                    "All traffic transmitted unencrypted.",
                                                    evidence=target,
                                                    remediation="Obtain a cert from Let's Encrypt and force HTTPS.")]),
        ("CORS Policy",              lambda: check_cors(session, target, timeout)),
        ("Cookie Security",          lambda: check_cookies(session, target, timeout)),
        ("Sensitive File Exposure",  lambda: check_sensitive_files(session, target, timeout, deep)),
        ("HTTP Methods",             lambda: check_http_methods(session, target, timeout)),
        ("Open Redirect",            lambda: check_open_redirect(session, target, timeout)),
        ("Directory Listing",        lambda: check_directory_listing(session, target, timeout)),
        ("Redirect Chain",           lambda: check_redirect_chain(session, target, timeout)),
        ("Rate Limiting",            lambda: check_rate_limiting(session, target, timeout)),
        ("Subresource Integrity",    lambda: check_subresource_integrity(session, target, timeout)),
        ("Information Disclosure",   lambda: check_info_disclosure(session, target, timeout)),
        ("Clickjacking",             lambda: check_clickjacking(session, target, timeout)),
        ("Host Header Injection",    lambda: check_host_header_injection(session, target, timeout)),
        ("Mixed Content",            lambda: check_mixed_content(session, target, timeout)),
        ("Content-Type Validation",  lambda: check_content_type(session, target, timeout)),
    ]

    for name, fn in modules:
        print(f"{Fore.MAGENTA}[~] {name}...{Style.RESET_ALL}")
        try:
            raw = fn()
        except Exception as exc:
            raw = [Finding(name, INFO, f"Module error: {exc}", "")]

        deduped = deduplicate(raw)
        sorted_results = sorted(deduped, key=lambda x: SEV_ORDER[x.severity])

        for f in sorted_results:
            if f.severity != PASS:
                print_finding(f, verbose=not quiet)
            else:
                print(f"    {SEV_COLOR[PASS]}✓ {f.title}{Style.RESET_ALL}")

        all_findings.extend(sorted_results)
        print()

    # Final dedup across all modules
    all_findings = deduplicate(all_findings)

    duration = time.monotonic() - t0
    counts   = {s: sum(1 for f in all_findings if f.severity == s)
                for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS]}
    score    = max(0, 100 - sum(SEV_WEIGHT[s] * counts[s]
                                for s in [CRITICAL, HIGH, MEDIUM, LOW]))

    print("=" * 62)
    print(f"  {Style.BRIGHT}SCAN COMPLETE  —  {duration:.1f}s{Style.RESET_ALL}")
    print("=" * 62)
    print(f"  Score    : {Style.BRIGHT}{score}/100{Style.RESET_ALL}")
    for sev in [CRITICAL, HIGH, MEDIUM, LOW, PASS]:
        print(f"  {SEV_COLOR[sev]}{sev:<10}{Style.RESET_ALL}: {counts[sev]}")
    print()

    if output:
        if output.endswith(".html"):
            generate_html_report(target, all_findings, duration, output)
        else:
            generate_text_report(target, all_findings, duration, output)
    else:
        generate_text_report(target, all_findings, duration, None)

    return all_findings
