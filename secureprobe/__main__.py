#!/usr/bin/env python3
"""
SecureProbe v2.0 — CLI Entry Point
"""

import sys
import textwrap
import argparse

def main():
    parser = argparse.ArgumentParser(
        prog="secureprobe",
        description="SecureProbe v2.0 — Web Security Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          secureprobe https://example.com
          secureprobe https://example.com --output report.html
          secureprobe https://example.com --deep --output report.html
          secureprobe https://example.com --output report.txt --quiet
          secureprobe http://192.168.1.100 --output audit.html

        Scan Modules (16 total):
          Security Headers    · SSL/TLS Config     · CORS Policy
          Cookie Security     · Sensitive Files     · HTTP Methods
          Open Redirect       · Directory Listing  · Redirect Chain
          Rate Limiting       · Subresource Integrity
          Info Disclosure     · Clickjacking        · Host Header Injection
          Mixed Content       · Content-Type Validation

        Severity Levels:
          🔴 CRITICAL  — Immediate exploitation risk  (score -15)
          🟠 HIGH      — Serious vulnerability         (score -8)
          🟡 MEDIUM    — Moderate risk                 (score -4)
          🔵 LOW       — Minor hardening issue         (score -1)
          ⚪ INFO      — Informational                 (no score impact)
          ✅ PASS      — Check passed

        ⚠  IMPORTANT: Only scan systems you own or have explicit written
           authorization to test. Unauthorized scanning is illegal in most
           countries regardless of intent.
        """),
    )

    parser.add_argument(
        "target",
        help="Target URL, domain, or IP  (e.g. https://example.com)",
    )
    parser.add_argument(
        "--deep", action="store_true",
        help="Deep scan: more paths, longer timeouts, full path list",
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Save report to file (.txt for text, .html for HTML dashboard)",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress per-finding verbose output (summary only in terminal)",
    )
    parser.add_argument(
        "--version", "-v", action="version", version="SecureProbe 2.0.0",
    )

    args = parser.parse_args()

    try:
        from secureprobe.scanner import run_scanner
        run_scanner(args.target, deep=args.deep, output=args.output,
                    quiet=args.quiet)
    except KeyboardInterrupt:
        try:
            from colorama import Fore, Style
            print(f"\n{Fore.YELLOW}[!] Scan interrupted.{Style.RESET_ALL}")
        except ImportError:
            print("\n[!] Scan interrupted.")
        sys.exit(0)
    except Exception as exc:
        print(f"[!] Fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
