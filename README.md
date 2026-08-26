# SQLi_XSS_tester

**SQL Injection** and **Cross-Site Scripting** scanner in pure Python (no third-party dependency), with blind injection detection, WAF bypass and report generation.

> Testing tool for authorized security audits (pentest, CTF, personal lab). Never use it against a target without explicit authorization.

## Features

- **Zero external dependency**: only Python 3.8+'s standard library (`urllib`, `html.parser`, `concurrent.futures`, `http.cookiejar`, `json`). No `pip install` required.
- **Automatic crawling** of forms and internal links (same origin, bounded depth).
- **~90 SQLi payloads + ~73 XSS payloads** per injection point (full arsenal by default, `--quick` mode available for a reduced ~14/~12 arsenal):
  - SQLi: authentication tautologies, UNION-based (1 to 12 columns), error-based across multiple DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), stacked queries, anti-WAF obfuscation (inline comments, case variation, encodings, whitespace alternatives), a bit of bonus NoSQL.
  - XSS: various tags/event handlers (`img`, `svg`, `video`, `details`, `marquee`, `iframe`, `object`…), attribute escaping, space/parenthesis-free bypasses, multiple encodings (named/decimal/hex HTML entities, single/double URL encoding, `\u`, tag splitting), polyglots.
  - SSTI: `{{7*7}}`, `${7*7}`, `#{7*7}` markers, etc., with an actual server-side evaluation check (looking for the computed result `49`, not just marker reflection).
- **Error-based / UNION-based SQLi** via multi-DBMS SQL error signatures.
- **Boolean-based blind SQLi**: compares the response of several `TRUE`/`FALSE` payload pairs and flags a significant length/status difference, rather than relying on a simple keyword.
- **Time-based blind SQLi**: measures the response time of `SLEEP`/`pg_sleep`/`WAITFOR DELAY`/`DBMS_LOCK.SLEEP` payloads (one per common DBMS) against a baseline request to detect an injection with no visible output.
- **SQLi authentication bypass** on login forms (detected via the presence of a `password` field, not just ≥2 text fields), compared against a baseline (unauthenticated) response rather than a simple absence of an error keyword — avoids the classic false positives of this kind of detection.
- **Reflected XSS with a unique canary**: each test injects a random token alongside the payload, to correctly attribute a reflection to *this specific* test rather than to a different payload that succeeded earlier in the scan (important on stateful pages, like a comment wall, that redisplay the whole history).
- **WAF block detection** and **automatic bypass**: URL encoding, alternating case, SQL comment injection (`/**/`), HTML entity encoding — automatically replayed if the initial payload gets blocked.
- **Concurrent scanning** (configurable thread pool), network retries (fast failure on an unreachable target), optional jitter.
- **Reports** in self-contained JSON and HTML.

## Usage

```bash
python3 SQLi_XSS_tester.py -u http://target.example/ [options]
```

### Main options

| Option | Description |
|---|---|
| `-u, --url` | Target URL (required) |
| `-t, --timeout` | Timeout per request (default: 10s) |
| `-w, --workers` | Concurrent threads (default: 8) |
| `--delay` | Random delay (0..delay s) between requests |
| `--max-pages` | Max pages crawled (default: 20) |
| `--no-crawl` | Only tests the given URL, no crawling |
| `--no-forms` | Disables form testing |
| `--no-blind` | Disables blind injection tests (faster) |
| `-q, --quick` | Reduced arsenal (~14 SQLi / ~12 XSS) for a fast triage pass |
| `--no-bypass` | Disables WAF bypass attempts |
| `--cookie` | Raw `Cookie` header |
| `-H, --header` | Additional header `"Name: value"` (repeatable) |
| `--proxy` | HTTP(S) proxy, e.g. `http://127.0.0.1:8080` (Burp/ZAP) |
| `-o, --output` | JSON report |
| `--html-report` | HTML report |
| `-y, --yes` | Skips the scope confirmation |
| `-v, --verbose` | Shows every test, not just positive results |

### Example

```bash
python3 SQLi_XSS_tester.py -u http://127.0.0.1:8000/ --html-report report.html -y
```

### Full arsenal vs. quick mode

The full arsenal (default) aims for maximum coverage: every backend/WAF has its own blind spots, so more variety in techniques and encodings raises the odds of finding the actual flaw. On a remote target with network latency and many forms/parameters discovered by the crawler, a full scan can take a while — adjust `--workers`, `--no-blind` (blind tests are the slowest because of the timing), or `--no-crawl` to target a known injection point directly. For quick recon across many targets, use `-q/--quick`.

## Security and ethics

On launch, the tool asks for explicit confirmation if the target isn't `localhost`/`127.0.0.1`. `-y` skips this confirmation in an automated environment.

## Known limitations

- XSS detection relies on the presence of the payload (or its decoded form) in the raw HTML; it doesn't simulate an actual DOM/JS environment and can miss purely DOM-based XSS (triggered only client-side, never passing through server HTML).
- Boolean-based blind SQLi detection compares response sizes: a target whose content already varies naturally (timestamp, dynamic content unrelated to the injection) can occasionally produce a false positive — manually verify `sqli-boolean-blind` results before treating them as confirmed.
- WAF bypass is heuristic and isn't guaranteed against every WAF, particularly commercial solutions with advanced contextual inspection.

## Development and testing

This script was developed and validated against a deliberately vulnerable, custom-built web lab (pure Python stdlib, 4 levels of increasing protection per flaw category: no protection, naive filter, WAF with a blind spot, and a secure implementation). This lab is a separate development tool, not included in this repository.
