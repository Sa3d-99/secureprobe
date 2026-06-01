"""
SecureProbe v2.0 — Unit Tests
Run with: pytest tests/ -v
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secureprobe.scanner import (
    Finding, deduplicate,
    CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS,
    SEV_ORDER, SEV_WEIGHT,
    check_security_headers, check_cors, check_cookies,
    check_http_methods, check_open_redirect,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Finding class
# ─────────────────────────────────────────────────────────────────────────────

class TestFinding:
    def test_basic_creation(self):
        f = Finding("TestMod", HIGH, "Test Title", "Description")
        assert f.module      == "TestMod"
        assert f.severity    == HIGH
        assert f.title       == "Test Title"
        assert f.description == "Description"
        assert f.evidence    == ""
        assert f.remediation == ""

    def test_dedup_key_stable(self):
        f1 = Finding("Mod", HIGH,   "Same Title")
        f2 = Finding("Mod", MEDIUM, "Same Title")
        assert f1._key == f2._key, "Same module+title should share dedup key"

    def test_dedup_key_differs_across_modules(self):
        f1 = Finding("ModA", HIGH, "Title")
        f2 = Finding("ModB", HIGH, "Title")
        assert f1._key != f2._key


# ─────────────────────────────────────────────────────────────────────────────
#  Deduplication
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplicate:
    def test_keeps_highest_severity(self):
        f_med  = Finding("Mod", MEDIUM,   "Duplicate Finding")
        f_crit = Finding("Mod", CRITICAL, "Duplicate Finding")
        f_low  = Finding("Mod", LOW,      "Duplicate Finding")
        result = deduplicate([f_med, f_crit, f_low])
        assert len(result) == 1
        assert result[0].severity == CRITICAL

    def test_different_titles_kept(self):
        f1 = Finding("Mod", HIGH, "Finding One")
        f2 = Finding("Mod", HIGH, "Finding Two")
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        assert deduplicate([]) == []

    def test_single_finding(self):
        f = Finding("Mod", HIGH, "Only One")
        assert deduplicate([f]) == [f]


# ─────────────────────────────────────────────────────────────────────────────
#  Security Headers (mock response)
# ─────────────────────────────────────────────────────────────────────────────

class MockResponse:
    """Minimal mock of requests.Response for header checks."""
    def __init__(self, headers: dict, status_code: int = 200,
                 text: str = "<html></html>"):
        self.headers     = headers
        self.status_code = status_code
        self.text        = text
        self.cookies     = []
        self.history     = []
        self.url         = "https://example.com"


class TestSecurityHeaders:
    def test_missing_csp_is_high(self):
        resp = MockResponse({"X-Content-Type-Options": "nosniff"})
        findings = check_security_headers(resp, "https://example.com")
        sevs = {f.title: f.severity for f in findings}
        assert sevs.get("Missing Content-Security-Policy") == HIGH

    def test_weak_csp_unsafe_inline(self):
        resp = MockResponse({
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"
        })
        findings = check_security_headers(resp, "https://example.com")
        titles = [f.title for f in findings]
        assert any("Weak" in t and "Content-Security-Policy" in t for t in titles)

    def test_missing_hsts_on_https(self):
        resp = MockResponse({"X-Content-Type-Options": "nosniff"})
        findings = check_security_headers(resp, "https://example.com")
        titles = [f.title for f in findings]
        assert any("HSTS" in t for t in titles)

    def test_hsts_not_checked_on_http(self):
        resp = MockResponse({})
        findings = check_security_headers(resp, "http://example.com")
        titles = [f.title for f in findings]
        assert not any("HSTS" in t for t in titles)

    def test_version_disclosure_server(self):
        resp = MockResponse({"Server": "Apache/2.4.51 (Debian)"})
        findings = check_security_headers(resp, "https://example.com")
        assert any("Version Disclosure" in f.title for f in findings)

    def test_good_headers_produce_passes(self):
        resp = MockResponse({
            "Content-Security-Policy": "default-src 'self'; object-src 'none'",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        })
        findings = check_security_headers(resp, "https://example.com")
        passes   = [f for f in findings if f.severity == PASS]
        critical = [f for f in findings if f.severity == CRITICAL]
        high     = [f for f in findings if f.severity == HIGH]
        assert len(critical) == 0
        assert len(high)     == 0
        assert len(passes)   >= 3


# ─────────────────────────────────────────────────────────────────────────────
#  Severity ordering / scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestSeveritySystem:
    def test_ordering(self):
        assert SEV_ORDER[CRITICAL] < SEV_ORDER[HIGH]
        assert SEV_ORDER[HIGH]     < SEV_ORDER[MEDIUM]
        assert SEV_ORDER[MEDIUM]   < SEV_ORDER[LOW]
        assert SEV_ORDER[LOW]      < SEV_ORDER[INFO]
        assert SEV_ORDER[INFO]     < SEV_ORDER[PASS]

    def test_weights(self):
        assert SEV_WEIGHT[CRITICAL] > SEV_WEIGHT[HIGH]
        assert SEV_WEIGHT[HIGH]     > SEV_WEIGHT[MEDIUM]
        assert SEV_WEIGHT[MEDIUM]   > SEV_WEIGHT[LOW]
        assert SEV_WEIGHT[INFO]     == 0
        assert SEV_WEIGHT[PASS]     == 0

    def test_score_calculation(self):
        findings = [
            Finding("A", CRITICAL, "C1"),
            Finding("B", HIGH,     "H1"),
            Finding("C", MEDIUM,   "M1"),
        ]
        score = max(0, 100 - sum(
            SEV_WEIGHT[f.severity] for f in findings
        ))
        # 100 - 15 - 8 - 4 = 73
        assert score == 73

    def test_score_floor_at_zero(self):
        findings = [Finding("X", CRITICAL, f"C{i}") for i in range(10)]
        score = max(0, 100 - sum(SEV_WEIGHT[f.severity] for f in findings))
        assert score == 0
