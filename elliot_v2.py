#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
 ███████╗██╗     ██╗     ██╗ ██████╗ ████████╗
 ██╔════╝██║     ██║     ██║██╔═══██╗╚══██╔══╝
 █████╗  ██║     ██║     ██║██║   ██║   ██║
 ██╔══╝  ██║     ██║     ██║██║   ██║   ██║
 ███████╗███████╗███████╗██║╚██████╔╝   ██║
 ╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝    ╚═╝
        H I D D E N   U R L   F I N D E R
              E L L I O T  |  v2.0
              A U T H O R :  N U R

 Hidden URL Finder — Async reconnaissance for authorized pentesting.
 ONLY use on systems you own or have written permission to test.
"""

# ═════════════════════════════════════════════════════════════
#  IMPORTS (stdlib first — nothing uses them before this block)
# ═════════════════════════════════════════════════════════════
import argparse
import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

# ═════════════════════════════════════════════════════════════
#  THIRD-PARTY (graceful failure)
# ═════════════════════════════════════════════════════════════
try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"[!] Missing dependency: {e.name}")
    print("[!] Fix: pip install -r requirements.txt")
    sys.exit(1)

# ═════════════════════════════════════════════════════════════
#  COLOR PALETTE — SINGLE SOURCE OF TRUTH
# ═════════════════════════════════════════════════════════════
class C:
    W    = '\033[97m'   # bright white
    DIM  = '\033[2m'    # dim
    R    = '\033[91m'   # red
    G    = '\033[92m'   # green
    Y    = '\033[93m'   # yellow
    GR   = '\033[90m'   # gray
    BOLD = '\033[1m'
    RST  = '\033[0m'
    # Aliases used elsewhere
    C    = '\033[96m'   # cyan
    M    = '\033[95m'   # magenta
    B    = '\033[94m'   # blue

# ═════════════════════════════════════════════════════════════
#  BANNER
# ═════════════════════════════════════════════════════════════
BANNER = f"""{C.W}{C.BOLD}
 ███████╗██╗     ██╗     ██╗ ██████╗ ████████╗
 ██╔════╝██║     ██║     ██║██╔═══██╗╚══██╔══╝
 █████╗  ██║     ██║     ██║██║   ██║   ██║
 ██╔══╝  ██║     ██║     ██║██║   ██║   ██║
 ███████╗███████╗███████╗██║╚██████╔╝   ██║
 ╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝    ╚═╝
{C.GR}
        H I D D E N   U R L   F I N D E R
              E L L I O T  |  v2.0
              A U T H O R :  N U R
{C.GR}────────────────────────────────────────────────────
{C.R}  [ ! ]  AUTHORIZED RECON — PENTEST / BUG BOUNTY
{C.GR}────────────────────────────────────────────────────{C.RST}
"""

# ═════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════
def ts() -> str:
    return f"{C.GR}[{datetime.now().strftime('%H:%M:%S')}]{C.RST}"

def info(m: str) -> None: print(f"{ts()} {C.W}[*]{C.RST} {m}")
def ok(m: str)   -> None: print(f"{ts()} {C.G}[+]{C.RST} {m}")
def warn(m: str) -> None: print(f"{ts()} {C.Y}[!]{C.RST} {m}")
def err(m: str)  -> None: print(f"{ts()} {C.R}[x]{C.RST} {m}")
def hit(m: str)  -> None: print(f"{ts()} {C.G}{C.BOLD}[*]{C.RST} {C.G}{m}{C.RST}")

def color_status(code: int) -> str:
    if code == 200:        return f"{C.G}{code}{C.RST}"
    if code in (301, 302): return f"{C.Y}{code}{C.RST}"
    if code in (401, 403): return f"{C.Y}{code}{C.RST}"
    if code >= 500:        return f"{C.R}{code}{C.RST}"
    return str(code)

# ═════════════════════════════════════════════════════════════
#  WORDLIST
# ═════════════════════════════════════════════════════════════
DEFAULT_WORDLIST = [
    # ── Admin ──
    "admin", "admin/", "admin.php", "admin/login", "administrator",
    "login", "login.php", "signin", "register", "auth",
    "wp-admin", "wp-login.php", "wp-json/wp/v2/users", "xmlrpc.php",
    "cpanel", "webmail", "phpmyadmin", "dashboard", "manager", "console",
    # ── Config / Secrets ──
    ".env", ".env.bak", ".env.prod", ".env.local",
    ".git/HEAD", ".git/config", ".gitignore", ".htaccess", ".htpasswd",
    "config.php", "config.php.bak", "config.yml", "config.json",
    "wp-config.php", "wp-config.php.bak", "settings.py",
    "credentials.json", "service-account.json",
    # ── Backups ──
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "site.zip", "db.sql", "database.sql", "dump.sql", "data.sql",
    # ── Logs / Debug ──
    "debug.log", "error.log", "access.log", "laravel.log",
    "phpinfo.php", "info.php", "test.php", "shell.php",
    "server-status", "actuator", "actuator/env",
    # ── Standard ──
    "robots.txt", "sitemap.xml", "humans.txt",
    ".well-known/security.txt", "security.txt",
    # ── Directories ──
    "api", "api/v1", "api/v2", "api/docs", "api/swagger.json",
    "graphql", "swagger", "swagger-ui", "openapi.json",
    "uploads", "files", "media", "assets", "static", "images",
    "docs", "dev", "test", "staging", "private", "internal",
    "secret", "hidden", "tmp", "cache", "logs", "old",
    # ── CMS ──
    "wp-content", "wp-content/uploads", "wp-content/plugins",
    "wp-includes", "sites/default", "sites/default/files",
    # ── Cloud ──
    ".aws/credentials", ".docker/config.json", "docker-compose.yml",
    "Dockerfile", "terraform.tfstate", "jenkins", ".gitlab-ci.yml",
    # ── Misc ──
    "health", "healthz", "status", "metrics", "ping", "version",
    "user", "users", "account", "profile", "settings", "search",
    "export", "import", "download", "install", "setup",
    "console", "debug", "trace", "sandbox",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# ═════════════════════════════════════════════════════════════
#  ENGINE
# ═════════════════════════════════════════════════════════════
class HiddenURLFinder:
    def __init__(self, base_url, concurrency=30, timeout=8.0, delay=0.0, depth=2):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.max_depth = depth
        self.session = None
        self.semaphore = None
        self.found = {}
        self.visited = set()
        self.lock = asyncio.Lock()

    # ── helpers ──
    def _is_internal(self, url):
        p = urlparse(url)
        return p.netloc == self.domain or p.netloc == ""

    def _normalize(self, url):
        return urljoin(self.base_url, url).split("#")[0]

    async def _record(self, url, status, source, size=0):
        async with self.lock:
            if url in self.found:
                return
            self.found[url] = {
                "url": url,
                "status": status,
                "size": size,
                "source": source,
                "time": datetime.now().isoformat(),
            }
            print(f"{ts()} {C.G}{C.BOLD}[*]{C.RST} {color_status(status)}  {url}  {C.GR}({source}){C.RST}")

    async def _fetch(self, url, method="GET", allow_redirects=False, max_body=500_000):
        async with self.semaphore:
            try:
                if self.delay:
                    await asyncio.sleep(self.delay)
                async with self.session.request(
                    method, url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=allow_redirects,
                    ssl=False,
                ) as r:
                    body = b""
                    if method == "GET":
                        try:
                            body = await r.content.read(max_body)
                        except Exception:
                            pass
                    return {
                        "status": r.status,
                        "headers": dict(r.headers),
                        "body": body,
                    }
            except Exception:
                return None

    # ── Phase 1: robots.txt & sitemap.xml ──
    async def robots_sitemap(self):
        info("Phase 1/4 → robots.txt & sitemap.xml")
        for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
            url = urljoin(self.base_url, path)
            r = await self._fetch(url)
            if r and r["status"] == 200:
                ok(f"Found {path}")
                await self._record(url, 200, "special")
                if path == "/robots.txt":
                    text = r["body"].decode(errors="ignore")
                    for line in text.splitlines():
                        low = line.strip().lower()
                        if low.startswith(("disallow:", "allow:")):
                            p = line.split(":", 1)[1].strip()
                            if p and p != "/":
                                await self._record(self._normalize(p), 200, "robots.txt")
        print()

    # ── Phase 2: concurrent brute-force ──
    async def brute_force(self, wordlist):
        info(f"Phase 2/4 → Brute-force {len(wordlist)} paths (concurrency={self.concurrency})")
        tasks = [self._probe(urljoin(self.base_url + "/", p)) for p in wordlist]
        await asyncio.gather(*tasks)
        print()

    async def _probe(self, url):
        r = await self._fetch(url)
        if not r:
            return
        if r["status"] in (200, 301, 302, 401, 403, 500):
            # Skip empty 200s (soft-404)
            if r["status"] == 200 and len(r["body"]) < 50:
                return
            await self._record(url, r["status"], "brute", len(r["body"]))

    # ── Phase 3: recursive crawl ──
    async def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited:
            return
        if not self._is_internal(url):
            return
        self.visited.add(url)
        r = await self._fetch(url)
        if not r or r["status"] != 200:
            return
        if "html" not in r["headers"].get("Content-Type", "").lower():
            return
        soup = BeautifulSoup(r["body"], "lxml")
        for tag in soup.find_all(["a", "link", "script", "img", "form", "iframe"]):
            attr = "href" if tag.name in ("a", "link") else "src"
            if tag.name == "form":
                attr = "action"
            v = tag.get(attr)
            if not v:
                continue
            full = self._normalize(v)
            if not self._is_internal(full):
                continue
            if full not in self.found:
                await self._record(full, 200, "crawler")
            if depth < self.max_depth:
                await self.crawl(full, depth + 1)

    # ── Phase 4: JS mining ──
    async def js_mine(self):
        info("Phase 4/4 → Mining JS files for endpoints")
        js_urls = [u for u in self.found if u.endswith(".js")][:30]
        if not js_urls:
            warn("No JS files found to mine")
            print()
            return
        for js in js_urls:
            r = await self._fetch(js)
            if not r or r["status"] != 200:
                continue
            text = r["body"].decode(errors="ignore")
            paths = set(re.findall(r'["\'](/[a-zA-Z0-9_\-/]{3,60})["\']', text))
            for p in paths:
                if any(x in p for x in (".png", ".jpg", ".css", ".svg", ".gif")):
                    continue
                full = self._normalize(p)
                if full not in self.found:
                    await self._record(full, 0, "js-mine")
        print()

    # ── runner ──
    async def run(self, wordlist):
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as s:
            self.session = s
            self.semaphore = asyncio.Semaphore(self.concurrency)

            start = time.time()
            await self.robots_sitemap()
            await self.brute_force(wordlist)
            info("Phase 3/4 → Crawling site structure")
            await self.crawl(self.base_url)
            print()
            await self.js_mine()
            self._summary(time.time() - start)

    def _summary(self, elapsed):
        print(f"{C.GR}{'=' * 60}{C.RST}")
        print(f"{C.W}{C.BOLD}  > SCAN COMPLETE{C.RST}")
        print(f"{C.GR}{'=' * 60}{C.RST}")
        print(f"  {C.GR}target :{C.RST} {self.base_url}")
        print(f"  {C.GR}found  :{C.RST} {C.G}{C.BOLD}{len(self.found)}{C.RST} URLs")
        print(f"  {C.GR}time   :{C.RST} {elapsed:.2f}s")
        print(f"{C.GR}{'=' * 60}{C.RST}")

        if self.found:
            print(f"\n{C.W}{C.BOLD}  > DISCOVERED{C.RST}")
            for url in sorted(self.found):
                print(f"  {C.GR}->{C.RST} {url}")
        else:
            warn("No results.")
        print()

    # ── exports ──
    def export_json(self, path):
        with open(path, "w") as f:
            json.dump({
                "target": self.base_url,
                "scanned_at": datetime.now().isoformat(),
                "total": len(self.found),
                "results": list(self.found.values()),
            }, f, indent=2)
        ok(f"JSON -> {path}")

    def export_txt(self, path):
        with open(path, "w") as f:
            for url in sorted(self.found):
                f.write(url + "\n")
        ok(f"TXT  -> {path}")

# ═════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        prog="elliot_v2",
        description="Hidden URL Finder — Elliot v2.0 (by NUR)",
    )
    p.add_argument("-u", "--url", required=True, help="Target URL (http/https)")
    p.add_argument("-w", "--wordlist", help="Custom wordlist file")
    p.add_argument("-o", "--output", help="Base name for exports (.json / .txt)")
    p.add_argument("-c", "--concurrency", type=int, default=30, help="Concurrent requests (default 30)")
    p.add_argument("-t", "--timeout", type=float, default=8.0, help="Timeout in seconds (default 8)")
    p.add_argument("-d", "--delay", type=float, default=0.0, help="Delay per request (default 0)")
    p.add_argument("--depth", type=int, default=2, help="Max crawl depth (default 2)")
    return p.parse_args()

def load_wordlist(path):
    if not path:
        return DEFAULT_WORDLIST
    if not os.path.isfile(path):
        err(f"Wordlist not found: {path}")
        sys.exit(1)
    with open(path, errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    ok(f"Loaded {len(lines)} entries from {path}")
    return lines

# ═════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════
def main():
    print(BANNER)
    args = parse_args()

    if not args.url.startswith(("http://", "https://")):
        err("URL must start with http:// or https://")
        sys.exit(1)

    warn("Only scan systems you own or have written permission to test.\n")
    wordlist = load_wordlist(args.wordlist)

    finder = HiddenURLFinder(
        base_url=args.url,
        concurrency=args.concurrency,
        timeout=args.timeout,
        delay=args.delay,
        depth=args.depth,
    )

    try:
        asyncio.run(finder.run(wordlist))
    except KeyboardInterrupt:
        warn("Interrupted by user.")
        return

    if args.output and finder.found:
        base = args.output.rsplit(".", 1)[0]
        finder.export_json(base + ".json")
        finder.export_txt(base + ".txt")

if __name__ == "__main__":
    main()