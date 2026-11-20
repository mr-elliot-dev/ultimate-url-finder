"""Shared HTTP/session helpers with rate-limit awareness and logging."""
import time
import logging
import requests
from urllib.parse import urljoin, urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("sec_assess")

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
    "(authorized-security-assessment)"
)

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close",
}


def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    return s


def safe_request(session, method, url, *, timeout=10, allow_redirects=True, **kw):
    """Wrapped request with error handling. Returns (response, error)."""
    try:
        r = session.request(
            method, url, timeout=timeout,
            allow_redirects=allow_redirects, **kw
        )
        return r, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL error: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection error: {e}"
    except requests.exceptions.Timeout:
        return None, "Timeout"
    except requests.exceptions.RequestException as e:
        return None, f"Request error: {e}"


def normalize_url(base: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def same_origin(base: str, url: str) -> bool:
    b, u = urlparse(base), urlparse(url)
    return (b.scheme, b.netloc) == (u.scheme, u.netloc)


def polite_sleep(seconds: float = 0.75):
    """Default inter-request delay to respect targets."""
    time.sleep(seconds)