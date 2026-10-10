#!/usr/bin/env python3
"""weavenames: registry-backed availability for a list of candidate names.

The model writes the names. This script is the only thing allowed to say
whether a domain is open, and it only says so when a registry answered.

    python3 weavenames.py check names.txt --out results.json --html names.html
    python3 weavenames.py show results.json --max-len 8 --open com
    python3 weavenames.py verify fretwise.com fretwise.ai

Standard library only, Python 3.9 or newer. Nothing to install.

How each status is earned:
  open      the TLD's registry has no record (an RDAP 404 served as
            application/rdap+json, or a WHOIS "not found"), and the registry
            passed a sanity check this run (google.<tld> came back registered).
            Shown as "open $11" only when Vercel also confirmed it is buyable at
            the standard price; otherwise "open*", price not verified.
  premium   no registry record, but the registrar prices it well above the
            TLD's standard price (needs VERCEL_TOKEN).
  reserved  no registry record, but the registrar will not sell it
            (reserved or blocked; needs VERCEL_TOKEN).
  taken     the registry returned a record.
  parked    taken, and its nameservers belong to a parking or domain-sale
            service, so it is probably for sale by a domainer.
  expiring  taken, but in redemption or pending delete.
  unknown   anything else: timeouts, rate limits after every retry, redirects,
            an answer this script could not parse, a registry that failed its
            sanity check. Never counted as open.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.2.1"
USER_AGENT = f"weavenames/{VERSION} (+https://github.com/weavenames/weavenames)"

OPEN = "open"
PREMIUM = "premium"
RESERVED = "reserved"
TAKEN = "taken"
PARKED = "parked"
EXPIRING = "expiring"
UNKNOWN = "unknown"
STATUSES = (OPEN, PREMIUM, RESERVED, TAKEN, PARKED, EXPIRING, UNKNOWN)

DEFAULT_TLDS = ("com",)

# Used only when the IANA bootstrap file cannot be fetched or cached.
FALLBACK_RDAP = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "ai": "https://rdap.identitydigital.services/rdap/",
    "app": "https://pubapi.registry.google/rdap/",
    "dev": "https://pubapi.registry.google/rdap/",
    "xyz": "https://rdap.centralnic.com/xyz/",
}
IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_MAX_AGE = 7 * 24 * 3600

# TLDs with no RDAP server in the IANA bootstrap, answered by the registry's
# own WHOIS. A reply must match exactly one of the two pattern sets; a reply
# that matches neither or both is unknown.
WHOIS = {
    "io": ("whois.nic.io", r"^Domain not found\.", r"^Creation Date:"),
    "co": ("whois.registry.co", r"DOMAIN NOT FOUND", r"^Creation Date:"),
    "sh": ("whois.nic.sh", r"^Domain not found\.", r"^Creation Date:"),
    "me": ("whois.nic.me", r"^Domain not found\.", r"^Creation Date:"),
    "so": ("whois.nic.so", r"No Object Found", r"^Creation Date:"),
    "gg": ("whois.gg", r"^NOT FOUND", r"^Registration status:"),
}

# Nameserver suffixes of parking and domain-sale services. Matched against
# the RDAP nameserver list of a taken domain.
PARKING_NS = (
    "sedoparking.com",
    "parkingcrew.net",
    "bodis.com",
    "above.com",
    "afternic.com",
    "dan.com",
    "undeveloped.com",
    "hugedomains.com",
    "namebrightdns.com",
    "domainmarket.com",
    "uniregistrymarket.link",
    "parklogic.com",
    "dnsnameservice.com",
    "smartname.com",
    "brandbucket.com",
    "squadhelp.com",
    "atom.com",
)
PENDING = ("pending delete", "pendingdelete", "redemption period", "redemptionperiod",
           "pending restore", "pendingrestore")

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
STYLE_RE = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
CANARY = "google"  # registered on every TLD this script supports; checked once per TLD per run


def valid_label(name: str) -> bool:
    """A label a registry will accept: LDH, and no '--' in positions 3-4
    unless it is a well-formed punycode (xn--) label."""

    if not NAME_RE.match(name):
        return False
    if name[2:4] == "--":
        if not name.startswith("xn--"):
            return False
        try:
            name.encode("ascii").decode("idna")
        except UnicodeError:
            return False
    return True
VERCEL_API = "https://api.vercel.com"
PREMIUM_RATIO = 1.5

# Per-host pacing. Google's registry (.app, .dev) returns 429 at 10 parallel
# requests and answers cleanly at one per second; WHOIS servers throttle by IP.
HOST_LIMITS = {
    "pubapi.registry.google": (1, 1.0),
    "api.vercel.com": (4, 0.1),
}
DEFAULT_HOST_LIMIT = (6, 0.0)
WHOIS_LIMIT = (1, 1.0)
RETRIES = 5
TIMEOUT = 15.0


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Gate:
    """Caps concurrency per host and spaces request starts."""

    def __init__(self, concurrency: int, interval: float) -> None:
        self.sem = threading.Semaphore(concurrency)
        self.interval = interval
        self.lock = threading.Lock()
        self.next_at = 0.0

    def __enter__(self) -> "Gate":
        self.sem.acquire()
        if self.interval:
            with self.lock:
                wait = self.next_at - time.monotonic()
                self.next_at = max(self.next_at, time.monotonic()) + self.interval
            if wait > 0:
                time.sleep(wait)
        return self

    def __exit__(self, *exc: object) -> None:
        self.sem.release()


_gates: dict[str, Gate] = {}
_gates_lock = threading.Lock()


def gate_for(host: str, whois: bool = False) -> Gate:
    key = ("whois:" if whois else "") + host
    with _gates_lock:
        if key not in _gates:
            limit = WHOIS_LIMIT if whois else HOST_LIMITS.get(host, DEFAULT_HOST_LIMIT)
            _gates[key] = Gate(*limit)
        return _gates[key]


def backoff(attempt: int, retry_after: str | None = None) -> None:
    delay = min(16.0, 2.0 ** attempt) + random.uniform(0, 0.5)
    if retry_after and retry_after.strip().isdigit():
        delay = min(30.0, max(delay, float(retry_after)))
    time.sleep(delay)


class CertError(Exception):
    """TLS certificate verification failed. Retrying cannot fix this."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A registry answers in place. A redirect is not an answer, and following
    # one would forward Authorization headers to another host.
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http_get(url: str, headers: dict[str, str] | None = None) -> tuple[int | None, bytes, str, str]:
    """GET with per-host pacing and retries on 429, 5xx and network errors.
    Redirects are never followed; they come back as their 3xx status.

    Returns (status, body, error, content_type). status is None when every
    attempt failed without an HTTP answer.
    """

    host = urllib.parse.urlparse(url).hostname or ""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    last_err = ""
    for attempt in range(RETRIES):
        retry_after = None
        try:
            with gate_for(host):
                req = urllib.request.Request(url, headers=hdrs)
                with _opener.open(req, timeout=TIMEOUT) as r:
                    return r.status, r.read(), "", r.headers.get("Content-Type", "") or ""
        except urllib.error.HTTPError as e:
            try:
                body = e.read() or b""
            except Exception:  # an HTTPError with no body raises on 3.9
                body = b""
            ctype = (e.headers.get("Content-Type", "") if e.headers else "") or ""
            if e.code == 429 or e.code >= 500:
                last_err = f"HTTP {e.code}"
                retry_after = e.headers.get("Retry-After") if e.headers else None
            else:
                return e.code, body, "", ctype
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLCertVerificationError) or isinstance(e, ssl.SSLCertVerificationError):
                raise CertError(str(reason)) from None
            last_err = f"{type(e).__name__}: {reason}"
        if attempt < RETRIES - 1:
            backoff(attempt, retry_after)
    return None, b"", last_err or "no answer", ""


def json_object(body: bytes) -> dict | None:
    """Parse a JSON object. Anything else (a list, null, garbage) is None."""

    try:
        doc = json.loads(body) if body else {}
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def whois_query(server: str, query: str) -> tuple[str | None, str]:
    last_err = ""
    for attempt in range(RETRIES):
        try:
            with gate_for(server, whois=True):
                with socket.create_connection((server, 43), timeout=TIMEOUT) as s:
                    s.settimeout(TIMEOUT)
                    s.sendall((query + "\r\n").encode())
                    chunks = []
                    while True:
                        c = s.recv(4096)
                        if not c:
                            break
                        chunks.append(c)
            text = b"".join(chunks).decode("utf-8", "replace")
            if text.strip():
                return text, ""
            last_err = "empty reply"
        except OSError as e:
            last_err = f"{type(e).__name__}: {e}"
        if attempt < RETRIES - 1:
            backoff(attempt)
    return None, last_err


# --- RDAP bootstrap ----------------------------------------------------------


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "weavenames"


_bootstrap: dict[str, str] | None = None
_bootstrap_lock = threading.Lock()


def rdap_base(tld: str) -> str | None:
    global _bootstrap
    with _bootstrap_lock:
        if _bootstrap is None:
            _bootstrap = load_bootstrap()
    return _bootstrap.get(tld)


def load_bootstrap() -> dict[str, str]:
    path = cache_dir() / "rdap-dns.json"
    data = None
    try:
        if path.exists() and time.time() - path.stat().st_mtime < BOOTSTRAP_MAX_AGE:
            data = json.loads(path.read_text())
    except (OSError, ValueError):
        data = None
    if data is None:
        status, body, _, _ = http_get(IANA_BOOTSTRAP)
        if status == 200:
            data = json_object(body)
            if data is not None:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                except OSError:
                    pass
    out = dict(FALLBACK_RDAP)
    if isinstance(data, dict):
        for service in data.get("services", []) or []:
            if not (isinstance(service, list) and len(service) == 2):
                continue
            tlds, urls = service
            https = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
            if not https:
                continue  # an http-only server can be answered by anyone on the path
            for t in tlds:
                out[str(t).lower()] = https[0] if https[0].endswith("/") else https[0] + "/"
    return out


# --- domain checks -----------------------------------------------------------


def result(domain: str, status: str, **kw: object) -> dict:
    out = {"domain": domain, "status": status}
    out.update(kw)
    return out


def parked_by(nameservers: list[str]) -> str | None:
    for ns in nameservers:
        for suffix in PARKING_NS:
            if ns == suffix or ns.endswith("." + suffix):
                return suffix
    return None


def check_rdap(name: str, tld: str, base: str) -> dict:
    domain = f"{name}.{tld}"
    url = f"{base}domain/{domain}"
    status, body, err, ctype = http_get(url, {"Accept": "application/rdap+json, application/json"})
    evidence = {"source": url, "answer": status if status is not None else err, "at": now_iso()}
    if status is None:
        return result(domain, UNKNOWN, registry=evidence, note=f"registry did not answer ({err})")
    if status == 404:
        # A registry's 404 is the authoritative "no such domain", and every
        # registry probed sends it as application/rdap+json. A 404 from a
        # proxy, a captive portal or a moved server is an HTML page or a JSON
        # error saying there is no RDAP service (rdap.org does this for every
        # .io name). Neither is an answer.
        if "application/rdap+json" not in ctype.lower():
            return result(domain, UNKNOWN, registry=evidence,
                          note=f"404 was not an RDAP reply (Content-Type {ctype or 'missing'})")
        doc = json_object(body) or {}
        title = str(doc.get("title", "")) + " " + " ".join(map(str, doc.get("description", []) or []))
        if "no rdap service" in title.lower():
            return result(domain, UNKNOWN, registry=evidence, note="no RDAP service for this TLD")
        return result(domain, OPEN, registry=evidence)
    if status != 200:
        return result(domain, UNKNOWN, registry=evidence, note=f"registry answered HTTP {status}")
    doc = json_object(body)
    if doc is None:
        return result(domain, UNKNOWN, registry=evidence, note="registry reply was not a JSON object")
    ldh = str(doc.get("ldhName", "")).lower().rstrip(".")
    if doc.get("objectClassName") != "domain" or ldh != domain:
        return result(domain, UNKNOWN, registry=evidence, note="registry reply was not this domain's record")
    statuses = [str(s).lower() for s in doc.get("status", []) or []]
    nameservers = [str(n.get("ldhName", "")).lower().rstrip(".")
                   for n in doc.get("nameservers", []) or [] if isinstance(n, dict)]
    expires = None
    for ev in doc.get("events", []) or []:
        if isinstance(ev, dict) and ev.get("eventAction") == "expiration":
            expires = str(ev.get("eventDate", ""))[:10] or None
    extra = {"registry": evidence, "nameservers": nameservers[:4]}
    if expires:
        extra["expires"] = expires
    if any(s in PENDING for s in statuses):
        return result(domain, EXPIRING, note="registry status: " + ", ".join(statuses), **extra)
    parker = parked_by(nameservers)
    if parker:
        return result(domain, PARKED, note=f"nameservers at {parker}", **extra)
    return result(domain, TAKEN, **extra)


def check_whois(name: str, tld: str) -> dict:
    server, free_re, taken_re = WHOIS[tld]
    domain = f"{name}.{tld}"
    text, err = whois_query(server, domain)
    evidence = {"source": f"whois://{server}", "answer": "reply" if text else err, "at": now_iso()}
    if text is None:
        return result(domain, UNKNOWN, registry=evidence, note=f"WHOIS did not answer ({err})")
    free = re.search(free_re, text, re.I | re.M) is not None
    taken = re.search(taken_re, text, re.I | re.M) is not None
    if free and not taken:
        evidence["answer"] = "not found"
        return result(domain, OPEN, registry=evidence)
    if taken and not free:
        evidence["answer"] = "record"
        return result(domain, TAKEN, registry=evidence)
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:120]
    return result(domain, UNKNOWN, registry=evidence, note=f"unrecognized WHOIS reply: {first}")


def lookup(name: str, tld: str) -> dict:
    base = rdap_base(tld)
    if base:
        return check_rdap(name, tld, base)
    if tld in WHOIS:
        return check_whois(name, tld)
    return result(f"{name}.{tld}", UNKNOWN, note=f"no RDAP or known WHOIS server for .{tld}")


_canary: dict[str, dict] = {}
_canary_locks: dict[str, threading.Lock] = {}
_canary_guard = threading.Lock()


def canary(tld: str) -> dict:
    """Look up a name known to be registered, once per TLD per run. If the
    registry does not return it as registered, nothing it says about other
    names on that TLD is trusted."""

    with _canary_guard:
        lock = _canary_locks.setdefault(tld, threading.Lock())
    with lock:
        if tld not in _canary:
            _canary[tld] = lookup(CANARY, tld)
        return _canary[tld]


def check_domain(name: str, tld: str) -> dict:
    res = lookup(name, tld)
    if res["status"] == OPEN:
        probe = canary(tld)
        if probe["status"] not in (TAKEN, PARKED, EXPIRING):
            res["status"] = UNKNOWN
            res["note"] = (f"registry failed its sanity check: {CANARY}.{tld} came back "
                           f"{probe['status']}, so its 'no record' answers are not trusted")
    return res


# --- registrar refinement (optional, Vercel) ----------------------------------


class Vercel:
    """Asks Vercel's registrar whether an unregistered domain is buyable, and
    at what price. A registry 404 cannot tell premium or reserved names apart
    from ordinary ones; a registrar can.

    A row is marked verified only when the registrar said available, returned
    a price, the TLD's standard price is known, and the price is within the
    premium ratio of it. Every other open row stays open*."""

    def __init__(self, token: str) -> None:
        self.headers = {"Authorization": f"Bearer {token}"}
        self.team = os.environ.get("VERCEL_TEAM_ID")
        self.base_prices: dict[str, float] = {}
        self.lock = threading.Lock()

    def _get(self, path: str) -> tuple[int | None, dict]:
        url = VERCEL_API + path + (f"?teamId={urllib.parse.quote(self.team)}" if self.team else "")
        status, body, _, _ = http_get(url, self.headers)
        return status, json_object(body) or {}

    def token_works(self, tld: str) -> tuple[bool, str]:
        status, doc = self._get(f"/v1/registrar/tlds/{tld}/price")
        if status == 200 and isinstance(doc.get("purchasePrice"), (int, float)):
            with self.lock:
                self.base_prices[tld] = float(doc["purchasePrice"])
            return True, ""
        return False, f"Vercel answered {status if status is not None else 'nothing'}"

    def base_price(self, tld: str) -> float | None:
        with self.lock:
            if tld in self.base_prices:
                return self.base_prices[tld]
        status, doc = self._get(f"/v1/registrar/tlds/{tld}/price")
        price = doc.get("purchasePrice") if status == 200 else None
        if not isinstance(price, (int, float)):
            return None  # not remembered: the next row asks again
        with self.lock:
            self.base_prices[tld] = float(price)
        return float(price)

    def refine(self, res: dict, tld: str) -> dict:
        domain = res["domain"]
        at = now_iso()
        status, doc = self._get(f"/v1/registrar/domains/{domain}/availability")
        if status != 200 or not isinstance(doc.get("available"), bool):
            res["registrar"] = {"source": "vercel", "answer": status, "verified": False, "at": at}
            res["note"] = "registrar check failed; price not verified"
            return res
        if not doc["available"]:
            res["registrar"] = {"source": "vercel", "available": False, "at": at}
            res["status"] = RESERVED
            res["note"] = "registry has no record but the registrar will not sell it"
            return res
        status, doc = self._get(f"/v1/registrar/domains/{domain}/price")
        price = doc.get("purchasePrice") if status == 200 else None
        base = self.base_price(tld)
        reg = {"source": "vercel", "available": True, "verified": False, "at": at}
        if isinstance(price, (int, float)):
            reg["price"] = float(price)
            years = doc.get("years")
            if isinstance(years, int):
                reg["years"] = years
        if base is not None:
            reg["standard_price"] = base
        res["registrar"] = reg
        if not isinstance(price, (int, float)):
            res["note"] = "buyable, but the registrar returned no price; price not verified"
        elif base is None:
            res["note"] = "standard price for this TLD unavailable; price not verified"
        elif price > base * PREMIUM_RATIO:
            res["status"] = PREMIUM
            res["note"] = f"priced ${price:,.2f} against a standard ${base:,.2f}"
        else:
            reg["verified"] = True
        return res


def vercel_from_env() -> Vercel | None:
    token = os.environ.get("VERCEL_TOKEN")
    return Vercel(token) if token else None


def vercel_checked(tlds: list[str], no_price: bool) -> Vercel | None:
    """Vercel client after a token check, or None (with a stderr line saying
    why) so a bad token runs unpriced instead of silently half-priced."""

    if no_price:
        return None
    v = vercel_from_env()
    if not v:
        return None
    ok, why = v.token_works(tlds[0])
    if not ok:
        print(f"VERCEL_TOKEN did not work ({why}); running without price checks, "
              "so open names show as open*", file=sys.stderr)
        return None
    return v


# --- input -------------------------------------------------------------------


def parse_tlds(value: str | None) -> list[str]:
    if not value:
        return list(DEFAULT_TLDS)
    out: list[str] = []
    for t in value.split(","):
        t = t.strip().lower().lstrip(".")
        if "." in t:
            raise ValueError(f".{t}: multi-label extensions such as .co.uk are not supported")
        if t and t not in out:
            out.append(t)
    return out or list(DEFAULT_TLDS)


def read_names(path: str) -> tuple[list[dict], list[str]]:
    """One name per line, optionally followed by a style word. '#' starts a
    comment. Returns (entries, rejected lines)."""

    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    seen: set[str] = set()
    entries: list[dict] = []
    rejected: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"[\s,|]+", line, maxsplit=1)
        name = parts[0].lower()
        style = parts[1].strip().lower() if len(parts) > 1 and parts[1].strip() else None
        if name.count(".") == 1 and name.split(".")[0]:
            name = name.split(".")[0]
        if not valid_label(name) or (style and not STYLE_RE.match(style)):
            rejected.append(raw.strip())
            continue
        if name in seen:
            continue
        seen.add(name)
        entries.append({"name": name, "style": style, "length": len(name)})
    return entries, rejected


# --- run ---------------------------------------------------------------------


def run_checks(entries: list[dict], tlds: list[str], workers: int,
               vercel: Vercel | None, progress: bool = True) -> None:
    jobs = []
    for e in entries:
        e["domains"] = {}
        for t in tlds:
            jobs.append((e, t))

    def work(job: tuple) -> None:
        e, tld = job
        try:
            res = check_domain(e["name"], tld)
            if vercel and res["status"] == OPEN:
                res = vercel.refine(res, tld)
        except CertError:
            raise
        except Exception as exc:  # one bad answer must not sink the run
            res = result(f"{e['name']}.{tld}", UNKNOWN, note=f"check failed: {type(exc).__name__}: {exc}")
        e["domains"][tld] = res

    total = len(jobs)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(work, j) for j in jobs]
        try:
            for f in concurrent.futures.as_completed(futures):
                f.result()
                done += 1
                if progress and (done % 25 == 0 or done == total):
                    print(f"  checked {done}/{total}", file=sys.stderr)
        except CertError:
            for f in futures:
                f.cancel()
            raise


# --- filtering and display ---------------------------------------------------


def status_of(entry: dict, tld: str) -> str:
    return entry.get("domains", {}).get(tld, {}).get("status", UNKNOWN)


def apply_filters(entries: list[dict], tlds: list[str], args: argparse.Namespace) -> list[dict]:
    must_open = parse_tlds(args.open) if args.open else []
    if args.available_only and tlds[0] not in must_open:
        must_open.insert(0, tlds[0])
    styles = {s.strip().lower() for s in args.style.split(",")} if args.style else None
    include = [w.lower() for w in (args.include or [])]
    exclude = [w.lower() for w in (args.exclude or [])]
    out = []
    for e in entries:
        n = e["name"]
        if args.min_len and len(n) < args.min_len:
            continue
        if args.max_len and len(n) > args.max_len:
            continue
        if include and not all(w in n for w in include):
            continue
        if exclude and any(w in n for w in exclude):
            continue
        if styles and (e.get("style") or "") not in styles:
            continue
        if any(status_of(e, t) != OPEN for t in must_open):
            continue
        if args.any_open and not any(status_of(e, t) == OPEN for t in tlds):
            continue
        out.append(e)
    return out


STATUS_RANK = {OPEN: 0, PREMIUM: 1, EXPIRING: 2, PARKED: 3, RESERVED: 4, TAKEN: 5, UNKNOWN: 6}


def sort_key(e: dict, tlds: list[str]) -> tuple:
    return (
        STATUS_RANK.get(status_of(e, tlds[0]), 9),
        -sum(1 for t in tlds if status_of(e, t) == OPEN),
        e["length"],
        e["name"],
    )


def price_verified(res: dict) -> bool:
    return bool((res.get("registrar") or {}).get("verified"))


def cell(res: dict | None) -> str:
    if not res:
        return "-"
    s = res.get("status", UNKNOWN)
    reg = res.get("registrar") or {}
    price = reg.get("price")
    years = reg.get("years")
    per = f"/{years}y" if isinstance(years, int) and years > 1 else ""
    if s == OPEN:
        if price_verified(res):
            return f"open ${price:,.0f}{per}"
        return f"open* ${price:,.0f}{per}" if isinstance(price, (int, float)) else "open*"
    if s == PREMIUM and price is not None:
        return f"premium ${price:,.0f}{per}"
    return s


def render_text(doc: dict, shown: list[dict], filters_desc: str) -> str:
    tlds = doc["tlds"]
    headers = ["name", "len", "style"] + ["." + t for t in tlds]
    rows = []
    for e in shown:
        row = [e["name"], str(e["length"]), e.get("style") or ""]
        row += [cell(e["domains"].get(t)) for t in tlds]
        rows.append(row)
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = []
    total = len(doc["names"])
    checked = doc.get("checked_at", "")
    try:
        local = parse_time(checked).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    except ValueError:
        local = checked
    head = f"{len(shown)} of {total} names, checked {local}"
    if filters_desc:
        head += f" (filters: {filters_desc})"
    lines.append(head)
    lines.append("")
    lines.append("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip())
    for r in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())
    counts = {s: 0 for s in STATUSES}
    for e in doc["names"]:
        counts[status_of(e, tlds[0])] = counts.get(status_of(e, tlds[0]), 0) + 1
    lines.append("")
    lines.append(f".{tlds[0]} across all {total}: " + ", ".join(f"{v} {k}" for k, v in counts.items() if v))
    unverified = [e["domains"][t] for e in shown for t in tlds
                  if t in e["domains"] and e["domains"][t].get("status") == OPEN
                  and not price_verified(e["domains"][t])]
    if unverified:
        lines.append("open* = the registry has no record, but the price was not verified, so a premium")
        if doc.get("registrar"):
            lines.append("        or reserved name is not ruled out. See the row's note in results.json.")
        else:
            lines.append("        or reserved name is not ruled out. Set VERCEL_TOKEN to check prices.")
    if any(e["domains"].get(t, {}).get("status") == UNKNOWN for e in doc["names"] for t in tlds):
        lines.append("unknown = no usable registry answer. Not counted as open.")
    return "\n".join(lines)


def parse_time(value: str) -> datetime:
    t = datetime.fromisoformat(value)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def describe_filters(args: argparse.Namespace, tlds: list[str]) -> str:
    parts = []
    if args.available_only:
        parts.append(f".{tlds[0]} open")
    if args.open:
        parts.append("open on " + ",".join("." + t for t in parse_tlds(args.open)))
    if args.any_open:
        parts.append("open on any checked TLD")
    if args.min_len:
        parts.append(f"length >= {args.min_len}")
    if args.max_len:
        parts.append(f"length <= {args.max_len}")
    for w in args.include or []:
        parts.append(f"contains '{w}'")
    for w in args.exclude or []:
        parts.append(f"without '{w}'")
    if args.style:
        parts.append(f"style {args.style}")
    return ", ".join(parts)


# --- HTML view ---------------------------------------------------------------

HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>weavenames: __TITLE__</title>
<style>
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; background: #fafaf8; color: #1d1d1b; font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
header { padding: 28px 32px 8px; }
h1 { margin: 0 0 4px; font-size: 20px; font-weight: 600; }
.sub { color: #6b6b66; font-size: 13px; }
.controls { position: sticky; top: 0; background: #fafaf8; border-bottom: 1px solid #e6e5e0; padding: 12px 32px; display: flex; flex-wrap: wrap; gap: 14px 22px; align-items: center; z-index: 1; }
.controls label { font-size: 13px; color: #44443f; display: inline-flex; gap: 6px; align-items: center; }
.controls input[type=text], .controls input[type=number], .controls select { font: inherit; font-size: 13px; padding: 5px 8px; border: 1px solid #d4d3cc; border-radius: 6px; background: #fff; color: #1d1d1b; }
.controls input[type=number] { width: 58px; }
.count { margin-left: auto; font-size: 13px; color: #6b6b66; }
main { padding: 16px 32px 48px; display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 12px; }
.card { background: #fff; border: 1px solid #e6e5e0; border-radius: 10px; padding: 14px 16px; }
.name { font-size: 22px; font-weight: 600; letter-spacing: 0.01em; word-break: break-all; cursor: copy; }
.meta { font-size: 12px; color: #8a8a84; margin: 2px 0 10px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { font-size: 12px; padding: 2px 8px; border-radius: 999px; border: 1px solid #e0dfd9; color: #6b6b66; background: #f4f4f1; }
.chip.open { background: #e8f5ec; border-color: #b9dfc5; color: #1f6b3a; font-weight: 600; }
.chip.premium, .chip.expiring { background: #fdf3e1; border-color: #f0d49c; color: #8a5a00; }
.chip.taken, .chip.parked, .chip.reserved { text-decoration: line-through; color: #9a9a94; }
.chip.unknown { background: #fff; border-style: dashed; color: #8a8a84; }
footer { padding: 0 32px 40px; font-size: 12px; color: #8a8a84; max-width: 860px; }
.empty { grid-column: 1 / -1; color: #6b6b66; padding: 40px 0; text-align: center; }
</style></head>
<body>
<header><h1 id="title"></h1><div class="sub" id="sub"></div></header>
<div class="controls">
  <label>Contains <input type="text" id="inc" placeholder="word"></label>
  <label>Length <input type="number" id="minl" min="1" placeholder="min"> to <input type="number" id="maxl" min="1" placeholder="max"></label>
  <label>Style <select id="style"><option value="">any</option></select></label>
  <span id="tldboxes"></span>
  <label><input type="checkbox" id="hidetaken"> Hide names with no open domain</label>
  <span class="count" id="count"></span>
</div>
<main id="grid"></main>
<footer id="foot"></footer>
<script id="data" type="application/json">__DATA__</script>
<script>
const doc = JSON.parse(document.getElementById('data').textContent);
const tlds = doc.tlds, priced = !!doc.registrar;
const verified = r => !!(r && r.registrar && r.registrar.verified);
const $ = id => document.getElementById(id);
$('title').textContent = doc.description || 'Name candidates';
const when = new Date(doc.checked_at);
$('sub').textContent = doc.names.length + ' names, checked against the registries ' + when.toLocaleString();
const styles = [...new Set(doc.names.map(n => n.style).filter(Boolean))].sort();
for (const s of styles) { const o = document.createElement('option'); o.value = s; o.textContent = s; $('style').appendChild(o); }
for (const t of tlds) {
  const l = document.createElement('label');
  const c = document.createElement('input'); c.type = 'checkbox'; c.dataset.tld = t; c.checked = (t === tlds[0]);
  l.appendChild(c); l.appendChild(document.createTextNode('.' + t + ' open'));
  $('tldboxes').appendChild(l);
}
function chipText(t, r) {
  if (!r) return '.' + t + ' -';
  const p = r.registrar && r.registrar.price;
  const y = r.registrar && r.registrar.years > 1 ? '/' + r.registrar.years + 'y' : '';
  if (r.status === 'open') return '.' + t + (verified(r) ? ' open $' + Math.round(p) + y : ' open*' + (p != null ? ' $' + Math.round(p) + y : ''));
  if (r.status === 'premium') return '.' + t + ' premium' + (p != null ? ' $' + Math.round(p).toLocaleString() + y : '');
  return '.' + t + ' ' + r.status;
}
const rank = {open:0, premium:1, expiring:2, parked:3, reserved:4, taken:5, unknown:6};
function render() {
  const inc = $('inc').value.trim().toLowerCase();
  const minl = parseInt($('minl').value) || 0, maxl = parseInt($('maxl').value) || 99;
  const style = $('style').value;
  const need = [...document.querySelectorAll('#tldboxes input:checked')].map(c => c.dataset.tld);
  const hide = $('hidetaken').checked;
  const st = (n, t) => (n.domains[t] || {}).status || 'unknown';
  const list = doc.names.filter(n =>
    (!inc || n.name.includes(inc)) && n.length >= minl && n.length <= maxl &&
    (!style || n.style === style) && need.every(t => st(n, t) === 'open') &&
    (!hide || tlds.some(t => st(n, t) === 'open'))
  ).sort((a, b) => (rank[st(a, tlds[0])] - rank[st(b, tlds[0])]) ||
    (tlds.filter(t => st(b, t) === 'open').length - tlds.filter(t => st(a, t) === 'open').length) ||
    (a.length - b.length) || a.name.localeCompare(b.name));
  const grid = $('grid'); grid.replaceChildren();
  for (const n of list) {
    const card = document.createElement('div'); card.className = 'card';
    const nm = document.createElement('div'); nm.className = 'name'; nm.textContent = n.name; nm.title = 'Click to copy';
    nm.onclick = () => navigator.clipboard && navigator.clipboard.writeText(n.name);
    const meta = document.createElement('div'); meta.className = 'meta';
    meta.textContent = n.length + ' letters' + (n.style ? ' \\u00b7 ' + n.style : '');
    const chips = document.createElement('div'); chips.className = 'chips';
    for (const t of tlds) {
      const r = n.domains[t]; const c = document.createElement('span');
      c.className = 'chip ' + (r ? r.status : 'unknown'); c.textContent = chipText(t, r);
      if (r && r.note) c.title = r.note;
      chips.appendChild(c);
    }
    card.append(nm, meta, chips); grid.appendChild(card);
  }
  if (!list.length) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = 'No names match these filters.'; grid.appendChild(e); }
  $('count').textContent = list.length + ' of ' + doc.names.length + ' shown';
}
document.querySelectorAll('.controls input, .controls select').forEach(el => el.addEventListener('input', render));
const anyStar = doc.names.some(n => tlds.some(t => n.domains[t] && n.domains[t].status === 'open' && !verified(n.domains[t])));
$('foot').textContent = 'Open means the registry for that extension had no record when checked. A price with no star means the registrar also confirmed it sells at the standard price.' +
  (anyStar ? ' A star (*) means the price was not verified, so a premium or reserved name is not ruled out' + (priced ? '.' : '; add a Vercel token to check prices.') : '') +
  ' Unknown means no usable registry answer, and it is never counted as open. Click a name to copy it.';
render();
</script></body></html>
"""


def render_html(doc: dict) -> str:
    data = (json.dumps(doc, separators=(",", ":"))
            .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e"))
    title = html.escape(doc.get("description") or "name candidates")
    return HTML_TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data)


# --- commands ----------------------------------------------------------------


def add_filter_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("filters")
    g.add_argument("--available-only", action="store_true",
                   help="only names whose first TLD (default .com) is open")
    g.add_argument("--open", metavar="TLDS", help="only names open on all of these, e.g. com,ai")
    g.add_argument("--any-open", action="store_true", help="only names open on at least one checked TLD")
    g.add_argument("--min-len", type=int, default=0)
    g.add_argument("--max-len", type=int, default=0)
    g.add_argument("--include", action="append", metavar="WORD", help="name must contain WORD (repeatable)")
    g.add_argument("--exclude", action="append", metavar="WORD", help="name must not contain WORD (repeatable)")
    g.add_argument("--style", metavar="STYLES", help="comma list of styles to keep")
    g.add_argument("--limit", type=int, default=0, help="show at most N rows")


def emit(doc: dict, args: argparse.Namespace) -> None:
    tlds = doc["tlds"]
    shown = sorted(apply_filters(doc["names"], tlds, args), key=lambda e: sort_key(e, tlds))
    if args.limit:
        shown = shown[: args.limit]
    print(render_text(doc, shown, describe_filters(args, tlds)))
    if args.html:
        Path(args.html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.html).write_text(render_html(doc), encoding="utf-8")
        print(f"\nhtml view: {Path(args.html).resolve()}")


def cmd_check(args: argparse.Namespace) -> int:
    try:
        tlds = parse_tlds(args.tlds)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    entries, bad = read_names(args.names)
    if bad:
        print(f"skipped {len(bad)} line(s) that are not valid domain labels: "
              + ", ".join(bad[:8]) + (" ..." if len(bad) > 8 else ""), file=sys.stderr)
    if not entries:
        print("no valid names to check", file=sys.stderr)
        return 2
    description = args.description
    if args.description_file:
        description = Path(args.description_file).read_text(encoding="utf-8").strip()
    for target in (args.out, args.html):
        if target:
            Path(target).parent.mkdir(parents=True, exist_ok=True)
    try:
        vercel = vercel_checked(tlds, args.no_price)
        print(f"checking {len(entries)} names on {', '.join('.' + t for t in tlds)}"
              + (" with Vercel pricing" if vercel else ""), file=sys.stderr)
        started = time.monotonic()
        run_checks(entries, tlds, args.workers, vercel)
    except CertError as e:
        print(CERT_HELP.format(e), file=sys.stderr)
        return 3
    doc = {
        "tool": f"weavenames {VERSION}",
        "description": description,
        "checked_at": now_iso(),
        "seconds": round(time.monotonic() - started, 1),
        "tlds": tlds,
        "registrar": "vercel" if vercel else None,
        "names": entries,
    }
    if args.out:
        Path(args.out).write_text(json.dumps(doc, indent=1), encoding="utf-8")
        print(f"results: {Path(args.out).resolve()}", file=sys.stderr)
    emit(doc, args)
    return 0


CERT_HELP = ("TLS certificate check failed ({}). Every lookup would fail the same way, so the run "
             "stopped. On macOS with Python from python.org, run 'Install Certificates.command' in "
             "the Python folder under Applications, then try again.")


def cmd_show(args: argparse.Namespace) -> int:
    doc = json.loads(Path(args.results).read_text(encoding="utf-8"))
    try:
        age = (datetime.now(timezone.utc) - parse_time(doc["checked_at"])).total_seconds()
    except (KeyError, TypeError, ValueError):
        age = float("inf")
    if age > 24 * 3600:
        print("warning: these results are over a day old or undated. Re-run check before "
              "trusting an open domain.", file=sys.stderr)
    emit(doc, args)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    rc = 0
    vercel_cache: dict[str, Vercel | None] = {}
    for d in args.domains:
        d = d.strip().lower().rstrip(".")
        if "." not in d:
            d += ".com"
        name, tld = d.split(".", 1)
        if not valid_label(name) or "." in tld:
            print(f"{d}: not a second-level domain this tool checks")
            rc = 2
            continue
        try:
            if tld not in vercel_cache:
                vercel_cache[tld] = vercel_checked([tld], args.no_price)
            vercel = vercel_cache[tld]
            res = check_domain(name, tld)
            if vercel and res["status"] == OPEN:
                res = vercel.refine(res, tld)
        except CertError as e:
            print(CERT_HELP.format(e), file=sys.stderr)
            return 3
        reg = res.get("registry", {})
        line = f"{d}: {cell(res)}"
        if res.get("note"):
            line += f", {res['note']}"
        line += f"  [{reg.get('source', '?')} answered {reg.get('answer', '?')}]"
        print(line)
    return rc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="weavenames", description="Registry-backed name availability.")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="check a file of names (one per line, optional style word)")
    c.add_argument("names", help="names file, or - for stdin")
    c.add_argument("-d", "--description", default="", help="what the names are for, shown in the views")
    c.add_argument("--description-file", help="read the description from a file (no shell quoting)")
    c.add_argument("--tlds", help="comma list, default com")
    c.add_argument("--out", help="write the full results JSON here")
    c.add_argument("--html", help="write a filterable HTML view here")
    c.add_argument("--workers", type=int, default=16)
    c.add_argument("--no-price", action="store_true", help="skip the Vercel price check even if VERCEL_TOKEN is set")
    add_filter_args(c)
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("show", help="filter and re-display saved results without re-checking")
    s.add_argument("results")
    s.add_argument("--html", help="write a filterable HTML view here")
    add_filter_args(s)
    s.set_defaults(func=cmd_show)

    v = sub.add_parser("verify", help="check specific domains, e.g. fretwise.com")
    v.add_argument("domains", nargs="+")
    v.add_argument("--no-price", action="store_true")
    v.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
