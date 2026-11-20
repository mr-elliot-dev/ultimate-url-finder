"""
Module 1: WAF / Firewall detection.

Detection strategy (passive & observational):
  1. Signature-matching response headers (Server, X-Powered-By, Set-Cookie,
     X-Sucuri-ID, CF-Ray, X-Akamai-*, X-CDN, etc.)
  2. Signature-matching body content (error pages).
  3. Probing for common blocking behaviours using *benign* payloads
     (SQL quote, angle brackets) to observe responses — no evasion.
  4. Rate-limit detection via small burst of requests and observing 429/503.
  5. False-positive mitigation: corroborate signatures, compare to baseline.
"""
import re
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

from utils import safe_request, polite_sleep, log

# --- Known WAF signatures (headers, cookies, body regexes) ------------------
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {
            "server": r"cloudflare",
            "cf-ray": r".+",
            "cf-cache-status": r".+",
        },
        "cookies": [r"__cfduid", r"__cf_bm", r"cf_clearance"],
        "body": [r"Attention Required! \| Cloudflare"],
        "status": [403, 503],
    },
    "AWS WAF / CloudFront": {
        "headers": {"x-amz-cf-id": r".+", "via": r"cloudfront"},
        "cookies": [],
        "body": [r"Request blocked"],
        "status": [403],
    },
    "Akamai": {
        "headers": {"server": r"AkamaiGHost", "x-akamai-transformed": r".+"},
        "cookies": [r"ak_bmsc", r"bm_sz"],
        "body": [r"Reference #\d+\.[0-9a-f]+"],
        "status": [403],
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": r".+", "server": r"Sucuri"},
        "cookies": [],
        "body": [r"Access Denied - Sucuri Website Firewall"],
        "status": [403],
    },
    "Imperva / Incapsula": {
        "headers": {"x-iinfo": r".+", "x-cdn": r"Incapsula"},
        "cookies": [r"visid_incap", r"incap_ses"],
        "body": [r"Incapsula incident ID"],
        "status": [403],
    },
    "F5 BIG-IP ASM": {
        "headers": {"server": r"BIG-IP", "x-wa-info": r".+"},
        "cookies": [r"BIGipServer", r"TS[0-9a-f]{8}"],
        "body": [r"The requested URL was rejected\. Please consult with your administrator"],
        "status": [403],
    },
    "Barracuda": {
        "headers": {"server": r"Barracuda"},
        "cookies": [r"barra_counter_session"],
        "body": [r"Barracuda Networks"],
        "status": [403],
    },
    "ModSecurity": {
        "headers": {"server": r"Apache.*ModSecurity"},
        "cookies": [],
        "body": [r"ModSecurity", r"Not Acceptable!"],
        "status": [406],
    },
    "Fortinet FortiWeb": {
        "headers": {"server": r"FortiWeb"},
        "cookies": [r"FORTIWAFSID"],
        "body": [r"FortiWeb"],
        "status": [403],
    },
    "Fastly": {
        "headers": {"x-fastly-request-id": r".+", "via": r"varnish", "x-served-by": r"cache-.*"},
        "cookies": [],
        "body": [],
        "status": [403],
    },
}

BLOCK_STATUSES = {403, 406, 429, 503}
RATE_LIMIT_STATUSES = {429, 503}


@dataclass
class WAFReport:
    target: str
    detected_wafs: List[str] = field(default_factory=list)
    evidence: Dict[str, List[str]] = field(default_factory=dict)
    access_restricted: bool = False
    restriction_detail: str = ""
    rate_limited: bool = False
    rate_limit_detail: str = ""
    server_info: Dict[str, str] = field(default_factory=dict)
    false_positive_notes: List[str] = field(default_factory=list)
    raw_statuses: List[int] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class WAFDetector:
    def __init__(self, session, target: str, probes: int = 8, delay: float = 0.75):
        self.session = session
        self.target = target
        self.probes = probes
        self.delay = delay
        self.report = WAFReport(target=target)

    # ---------- signature matching ------------------------------------------
    def _match_headers(self, headers: Dict[str, str]):
        lower = {k.lower(): (v or "") for k, v in headers.items()}
        hits = []
        for waf, sig in WAF_SIGNATURES.items():
            header_hits = []
            for hname, pattern in sig.get("headers", {}).items():
                val = lower.get(hname, "")
                if val and re.search(pattern, val, re.I):
                    header_hits.append(f"{hname}: {val[:80]}")
            if header_hits:
                hits.append((waf, "header", header_hits))
        return hits

    def _match_cookies(self, set_cookie: str):
        hits = []
        if not set_cookie:
            return hits
        for waf, sig in WAF_SIGNATURES.items():
            for pat in sig.get("cookies", []):
                if re.search(pat, set_cookie):
                    hits.append((waf, "cookie", [f"Set-Cookie matches {pat}"]))
                    break
        return hits

    def _match_body(self, text: str):
        hits = []
        if not text:
            return hits
        for waf, sig in WAF_SIGNATURES.items():
            for pat in sig.get("body", []):
                m = re.search(pat, text, re.I)
                if m:
                    hits.append((waf, "body", [f"body matches: {m.group(0)[:80]}"]))
                    break
        return hits

    # ---------- main flow ---------------------------------------------------
    def run(self) -> WAFReport:
        log.info(f"[WAF] Baseline request → {self.target}")
        base_resp, err = safe_request(self.session, "GET", self.target)
        if err or base_resp is None:
            log.warning(f"[WAF] Baseline failed: {err}")
            return self.report

        base_status = base_resp.status_code
        self.report.raw_statuses.append(base_status)
        self.report.server_info = {
            k: v for k, v in base_resp.headers.items()
            if k.lower() in {"server", "x-powered-by", "via", "cf-ray", "x-amz-cf-id"}
        }

        self._collect_signatures(base_resp, origin="baseline")

        # Restriction baseline
        if base_status in BLOCK_STATUSES:
            self.report.access_restricted = True
            self.report.restriction_detail = (
                f"Baseline response already returned {base_status} — "
                f"target may be geo-blocked, IP-restricted, or require auth."
            )

        # Passive rate-limit / burst observation
        self._rate_limit_probe()

        # Benign payload probes to detect blocking behaviour
        self._benign_probe()

        self._finalize()
        return self.report

    # ---------- internals ---------------------------------------------------
    def _collect_signatures(self, resp, origin: str):
        header_hits = self._match_headers(resp.headers)
        cookie_hits = self._match_cookies(resp.headers.get("Set-Cookie", ""))
        body_hits = self._match_body(resp.text[:20000] if resp.text else "")

        for waf, kind, evidence in header_hits + cookie_hits + body_hits:
            if waf not in self.report.detected_wafs:
                self.report.detected_wafs.append(waf)
            self.report.evidence.setdefault(waf, []).extend(
                [f"[{origin}/{kind}] {e}" for e in evidence]
            )

        # Blocking status handling
        if resp.status_code in BLOCK_STATUSES:
            if resp.status_code in RATE_LIMIT_STATUSES:
                self.report.rate_limited = True
                self.report.rate_limit_detail = (
                    f"{origin} returned {resp.status_code} — likely rate limit / WAF throttling."
                )
            else:
                self.report.access_restricted = True
                self.report.restriction_detail = (
                    f"{origin} returned {resp.status_code} with benign request — "
                    f"possible WAF / access rule."
                )

    def _rate_limit_probe(self):
        """Issue a small, spaced burst and watch for 429/503 transitions."""
        statuses = []
        for i in range(min(self.probes, 5)):
            polite_sleep(self.delay)
            r, err = safe_request(self.session, "GET", self.target)
            if err or r is None:
                continue
            statuses.append(r.status_code)
            self.report.raw_statuses.append(r.status_code)
            self._collect_signatures(r, origin=f"burst#{i+1}")
            if r.status_code in RATE_LIMIT_STATUSES:
                self.report.rate_limited = True
                self.report.rate_limit_detail = (
                    f"Rate limit detected at request #{i+1} (status {r.status_code}). "
                    f"Check Retry-After: {r.headers.get('Retry-After', 'n/a')}"
                )
                break

        if statuses and any(s in RATE_LIMIT_STATUSES for s in statuses):
            self.report.rate_limited = True

    def _benign_probe(self):
        """
        Send benign but WAF-detectable payloads to observe blocking.
        Strictly observational — we do NOT attempt evasion.
        """
        probes = [
            ("quote", {"q": "'"}),
            ("angle", {"q": "<script>"}),
            ("traversal", {"q": "../../etc/passwd"}),
        ]
        for name, params in probes:
            polite_sleep(self.delay)
            r, err = safe_request(self.session, "GET", self.target, params=params)
            if err or r is None:
                continue
            self.report.raw_statuses.append(r.status_code)
            if r.status_code in BLOCK_STATUSES:
                self.report.access_restricted = True
                self.report.restriction_detail = (
                    f"Benign probe '{name}' triggered {r.status_code} — "
                    f"WAF or input filter present."
                )
                # Try to attribute to a signature
                self._collect_signatures(r, origin=f"probe:{name}")
                break

    def _finalize(self):
        # False-positive mitigation: single header match alone is weak.
        if self.report.detected_wafs:
            weak = []
            for waf in list(self.report.detected_wafs):
                ev = self.report.evidence.get(waf, [])
                # Corroboration: at least 2 pieces of evidence OR a cookie/body hit.
                strong = any(
                    "[header]" not in e and "header" not in e.split("]", 1)[0]
                    for e in ev
                ) or len(ev) >= 2
                if not strong and waf == "Fastly":
                    weak.append(waf)
            for w in weak:
                self.report.detected_wafs.remove(w)
                self.report.false_positive_notes.append(
                    f"Removed '{w}': only a single weak header match, insufficient corroboration."
                )

        # Fastly via 'via: varnish' alone is highly FP-prone — flag explicitly.
        if "Fastly" in self.report.detected_wafs:
            self.report.false_positive_notes.append(
                "Fastly signature based on Varnish headers may be a generic caching proxy — "
                "validate manually."
            )

        if not self.report.detected_wafs:
            self.report.false_positive_notes.append(
                "No WAF signatures detected — target may be unproxied or using an "
                "unnamed/custom WAF."
            )