"""
SecureProbe v2.0 — Web Security Audit Tool
https://github.com/men3m-4/secureprobe
"""

from .scanner import (
    Finding, run_scanner,
    CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS,
)

__version__ = "2.0.0"
__all__     = ["Finding", "run_scanner", "CRITICAL","HIGH","MEDIUM","LOW","INFO","PASS"]
