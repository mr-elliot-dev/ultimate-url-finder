"""
Module 2: Admin panel discovery.

What it does:
  * Crawls the base page for linked login/admin pages.
  * Parses authentication forms (password inputs, username/email fields).
  * For candidate admin endpoints, requests them *unauthenticated* and
    classifies the response:
        - 401/403 → protected
        - 200 + login form → protected (redirect to auth)
        - 200 + no auth indicators → possible unauth exposure (needs manual review)
  * Records public login endpoints separately.

IMPORTANT: This performs only GETs (no form submission, no credential tests).
"""
import re
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional

from bs4 import BeautifulSoup
from utils import safe_request, polite_sleep, same_origin, normalize_url, log


LOGIN_HINTS = re.compile(
    r"(login|signin|sign-in|auth|admin|wp-login|wp-admin|administrator|"
    r"user/login|account/login|dashboard|console|manage|panel|cms|backend)",
    re.I,
)
ADMIN_HINTS = re.compile(
    r"(admin|administrator|dashboard|console|manage|panel|backend|control|"
    r"wp-admin|cpanel|webadmin|adminpanel|admincp)", re.I
)

AUTH_INDICATORS = re.compile(
    r"(password|passwd|passcode|otp|one-time|2fa|mfa|sign\s*in|log\s*in)",
    re.I
)


@dataclass
class LoginForm:
    url: str
    action: str
    method: str
    fields: Dict[str, str] = field(default_factory=dict)
    has_password: bool = False
    has_hidden_csrf: bool = False


@dataclass
class AdminEndpoint:
    url: str
    status: int
    classification: str       # "protected" | "possibly_public" | "unknown"
    notes: str = ""


@dataclass
class AdminReport:
    target: str
    public_login_links: List[str] = field(default_factory=list)
    discovered_forms: List[Dict] = field(default_factory=list)
    admin_candidates: List[Dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class AdminDiscovery:
    def __init__(self, session, target: str, max_links: int = 60, delay: float = 0.6):
        self.session = session
        self.target = target
        self.max_links = max_links
        self.delay = delay
        self.report = AdminReport(target=target)
        self._seen: Set[str] = set()

    # ---------- public entry ------------------------------------------------
    def run(self) -> AdminReport:
        base_resp, err = safe_request(self.session, "GET", self.target)
        if err or base_resp is None or not base_resp.text:
            log.warning(f"[ADMIN] Baseline failed: {err}")
            return self.report

        soup = BeautifulSoup(base_resp.text, "html.parser")
        self._crawl_links(soup)
        self._crawl_forms(soup)

        # Probe inferred admin candidates (unauthenticated GETs)
        self._probe_admin_candidates()
        return self.report

    # ---------- crawling ----------------------------------------------------
    def _crawl_links(self, soup: BeautifulSoup):
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = normalize_url(self.target, href)
            if not same_origin(self.target, full):
                continue  # keep scope tight
            if full in self._seen:
                continue
            self._seen.add(full)

            text = (a.get_text() or "").strip()
            if LOGIN_HINTS.search(href) or LOGIN_HINTS.search(text):
                if full not in self.report.public_login_links:
                    self.report.public_login_links.append(full)
            if len(self._seen) >= self.max_links:
                break

        # Also probe a small curated set of conventional admin paths
        common = ["/admin", "/admin/login", "/login", "/administrator",
                  "/wp-admin", "/wp-login.php", "/dashboard", "/console",
                  "/manage", "/adminpanel", "/admin/login.php"]
        for path in common:
            full = normalize_url(self.target, path)
            if same_origin(self.target, full) and full not in self._seen:
                self._seen.add(full)
                if full not in self.report.admin_candidates:
                    pass  # probed later

    def _crawl_forms(self, soup: BeautifulSoup):
        # Also pull forms from discovered login pages
        pages = [self.target] + self.report.public_login_links[:10]
        seen_forms = set()
        for page in pages:
            polite_sleep(self.delay)
            r, err = safe_request(self.session, "GET", page)
            if err or r is None or not r.text:
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or page
                method = (form.get("method") or "GET").upper()
                action_full = normalize_url(page, action)
                if not same_origin(self.target, action_full):
                    continue
                fields = {}
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if not name:
                        continue
                    fields[name] = (inp.get("type") or "text").lower()
                has_pw = any(t == "password" for t in fields.values())
                has_csrf = any(
                    n.lower() in {"csrf", "csrf_token", "_token", "authenticity_token",
                                   "csrfmiddlewaretoken", "__requestverificationtoken"}
                    for n in fields
                )
                key = (action_full, method)
                if key in seen_forms:
                    continue
                seen_forms.add(key)
                lf = LoginForm(
                    url=page,
                    action=action_full,
                    method=method,
                    fields=fields,
                    has_password=has_pw,
                    has_hidden_csrf=has_csrf,
                )
                self.report.discovered_forms.append(asdict(lf))

    # ---------- admin probe -------------------------------------------------
    def _probe_admin_candidates(self):
        candidates = list(dict.fromkeys(
            self.report.public_login_links
            + [normalize_url(self.target, p) for p in [
                "/admin", "/administrator", "/wp-admin", "/dashboard",
                "/console", "/manage", "/admin/login", "/adminpanel",
            ]]
        ))

        for url in candidates:
            if not same_origin(self.target, url):
                continue
            polite_sleep(self.delay)
            r, err = safe_request(self.session, "GET", url, allow_redirects=False)
            if err or r is None:
                self.report.admin_candidates.append(asdict(AdminEndpoint(
                    url=url, status=0, classification="unknown",
                    notes=f"Error: {err}"
                )))
                continue

            cls, notes = self._classify(r)
            self.report.admin_candidates.append(asdict(AdminEndpoint(
                url=url, status=r.status_code, classification=cls, notes=notes
            )))

    def _classify(self, r) -> (str, str):
        if r.status_code in (401, 407):
            return "protected", f"HTTP {r.status_code} — auth required (WWW-Authenticate: " \
                                f"{r.headers.get('WWW-Authenticate', 'n/a')})"
        if r.status_code == 403:
            return "protected", "HTTP 403 — access forbidden (WAF/role restriction)"
        if 300 <= r.status_code < 400:
            loc = r.headers.get("Location", "")
            if LOGIN_HINTS.search(loc):
                return "protected", f"Redirect {r.status_code} → {loc} (auth redirect)"
            return "unknown", f"Redirect {r.status_code} → {loc}"
        if r.status_code == 200:
            body = r.text[:30000] if r.text else ""
            has_pw = bool(re.search(r'type\s*=\s*["\']password', body, re.I))
            has_auth = bool(AUTH_INDICATORS.search(body))
            if has_pw or has_auth:
                return "protected", "200 OK but login form present — auth gate"
            if ADMIN_HINTS.search(body):
                return "possibly_public", (
                    "200 OK, admin keywords present, no login form detected — "
                    "MANUAL REVIEW REQUIRED"
                )
            return "unknown", "200 OK — no auth or admin markers"
        if r.status_code == 404:
            return "unknown", "404 — not present"
        return "unknown", f"HTTP {r.status_code}"