#!/usr/bin/env python3
"""
Advanced Web Security & Admin Authentication Assessment Tool.

USAGE:
    python3 main.py https://target.example.com --json out.json

AUTHORIZATION: run only against assets you are permitted to test.
"""
import argparse
import json
import sys
from pathlib import Path

from utils import build_session, log
from waf_detector import WAFDetector
from admin_discovery import AdminDiscovery


def parse_args():
    p = argparse.ArgumentParser(description="Advanced Web Security & Admin Auth Assessment")
    p.add_argument("target", help="Base URL, e.g. https://target.example.com")
    p.add_argument("--delay", type=float, default=0.75, help="Delay between requests (seconds)")
    p.add_argument("--json", type=str, default=None, help="Write JSON report to this path")
    p.add_argument("--skip-waf", action="store_true")
    p.add_argument("--skip-admin", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        log.error("Target must start with http:// or https://")
        sys.exit(2)

    session = build_session()
    report = {"target": target, "modules": {}}

    if not args.skip_waf:
        log.info("=== Module 1: WAF / Firewall Detection ===")
        waf = WAFDetector(session, target, delay=args.delay)
        report["modules"]["waf"] = waf.run().to_dict()

    if not args.skip_admin:
        log.info("=== Module 2: Admin Panel Discovery ===")
        admin = AdminDiscovery(session, target, delay=args.delay)
        report["modules"]["admin"] = admin.run().to_dict()

    _print_summary(report)

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        log.info(f"JSON report → {args.json}")


def _print_summary(report):
    print("\n" + "=" * 70)
    print(f"TARGET: {report['target']}")
    print("=" * 70)

    waf = report["modules"].get("waf")
    if waf:
        print("\n[WAF DETECTION]")
        print(f"  Detected WAFs        : {waf['detected_wafs'] or 'none'}")
        print(f"  Access restricted    : {waf['access_restricted']}")
        if waf["restriction_detail"]:
            print(f"    └─ {waf['restriction_detail']}")
        print(f"  Rate limiting        : {waf['rate_limited']}")
        if waf["rate_limit_detail"]:
            print(f"    └─ {waf['rate_limit_detail']}")
        print(f"  Server info          : {waf['server_info']}")
        print(f"  Status sequence      : {waf['raw_statuses']}")
        if waf["evidence"]:
            print("  Evidence:")
            for w, ev in waf["evidence"].items():
                for e in ev[:4]:
                    print(f"    - {w}: {e}")
        if waf["false_positive_notes"]:
            print("  FP Notes:")
            for n in waf["false_positive_notes"]:
                print(f"    ⚠ {n}")

    admin = report["modules"].get("admin")
    if admin:
        print("\n[ADMIN DISCOVERY]")
        print(f"  Public login links   : {len(admin['public_login_links'])}")
        for u in admin["public_login_links"][:10]:
            print(f"    - {u}")
        print(f"  Auth forms found     : {len(admin['discovered_forms'])}")
        for f in admin["discovered_forms"][:6]:
            flag = "✓ pw" if f["has_password"] else "no-pw"
            csrf = " CSRF" if f["has_hidden_csrf"] else ""
            print(f"    - {f['method']} {f['action']} [{flag}{csrf}]")
        print(f"  Admin candidates     : {len(admin['admin_candidates'])}")
        for a in admin["admin_candidates"]:
            print(f"    - [{a['status']}] {a['classification']:<16} {a['url']}")
            if a["notes"]:
                print(f"        └─ {a['notes']}")


if __name__ == "__main__":
    main()