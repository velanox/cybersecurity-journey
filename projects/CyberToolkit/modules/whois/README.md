# WHOIS

A standalone WHOIS lookup module for CyberToolkit. No dependency on
Flask, HTML, or any web framework — every file under `modules/whois/`
can be imported and used from a plain Python script, a test suite, or a
web app alike. Zero third-party dependencies: everything runs on the
Python standard library (`socket`, `re`, `dataclasses`).

## What this does

WHOIS is a plain-text protocol over TCP port 43 — no HTTP involved. This
module:

1. **Validates** a domain string (cleans up pasted URLs/ports, rejects
   anything that isn't a plausible domain).
2. **Resolves** the right WHOIS server for the domain's TLD, using a
   static table of common TLDs, falling back to the IANA root server
   (`whois.iana.org`) for anything not in that table.
3. **Queries** that server over a raw socket, following a single
   referral hop if the response points elsewhere (the standard
   `refer:`/`whois:` convention).
4. **Parses** the (registry-specific, inconsistently formatted) response
   into structured fields: registrar, creation/update/expiry dates,
   status codes, nameservers.

## Architecture

```
modules/whois/
├── __init__.py
├── models.py          # typed reference shape (WhoisResult) — documentation only,
│                       # not instantiated at runtime (same pattern as hash_cracker)
├── validators.py      # validate_domain() + custom exceptions
├── servers.py         # TLD -> WHOIS server table + IANA fallback constant
├── query.py           # raw socket engine: send query, handle timeouts/DNS/connection errors,
│                       # follow one referral hop
├── parser.py           # tolerant text parser: multiple label variants per field,
│                       # "not found" detection
├── whois_lookup.py     # lookup_domain() — combines query.py + parser.py into one
│                       # always-structured result
├── test_fixtures.py    # sample raw WHOIS responses (Verisign/RIPE/JPRS/not-found/
│                       # malformed/redacted styles), reused by tests.py
└── tests.py            # unit tests, no Flask, no real network required
```

**Layering rule**: `validators.py`, `servers.py`, and `parser.py` are
pure functions with no I/O. `query.py` is the only file that touches a
socket. `whois_lookup.py` is the single entry point everything else
(Flask, a CLI, tests) should import.

## Input validation

`validate_domain()` cleans common paste mistakes (a scheme, a path, a
port, a trailing dot) and rejects:
- empty input
- email addresses (`user@example.com`)
- bare IP addresses (WHOIS for IPs uses a different protocol/server
  hierarchy entirely — out of scope)
- missing TLD (`example` alone)
- malformed labels (leading/trailing hyphens, empty labels)
- input over 253 characters (RFC 1035 limit)

Raises `WhoisValidationError` on any of the above — this is a caller
input problem, not a lookup outcome, so it's raised rather than folded
into the result (Flask catches it and returns 400).

## Network engine

`query_whois_server()` opens a raw TCP socket to port 43, sends the
domain followed by `\r\n`, and reads until the server closes the
connection (a WHOIS server doesn't do explicit request/response framing
beyond that). Raises:
- `WhoisTimeoutError` if the server doesn't respond in time
- `WhoisNetworkError` for DNS resolution failure, connection refusal, or
  any other socket-level `OSError`

`lookup_domain_raw()` wraps this with server resolution and one referral
hop: if the response contains a `refer:` or `whois:` line pointing
somewhere else, it queries that server too and returns its response
instead (falling back to the first response if the second hop itself
fails, so a failed referral doesn't lose whatever data was already
retrieved).

**Known limitation — single referral hop**: some registries (like
Verisign for `.com`) return registry-level data directly (sufficient for
this tool's fields) but a thin registry could in principle require a
second hop to a registrar-specific server for full detail. This module
does not chase a second hop, both to avoid unbounded referral chains and
because registry-level data already covers every field this tool
extracts in practice.

## Parser

Different registries format their WHOIS output differently — there is
no single universal standard (compare Verisign's `Creation Date:` to
JPRS's bracketed `[Created on]`). `parser.py` handles this by checking
several known label variants per field rather than assuming one format.
Verified against Verisign-style, RIPE-style, and JPRS-style (bracketed)
sample responses.

**Known limitation — JPRS registrar not extracted**: the `.jp` registry's
classic WHOIS output lists a `[Registrant]` but no explicit `[Registrar]`
line in many cases; `registrar` will legitimately be `None` for such
responses. This is a genuine registry quirk, not a missing label.

**"Not found" detection** is a substring-matching heuristic (`no match
for`, `not found`, `no entries found`, `is available for registration`,
etc.) — necessarily broad, since there's no standard "domain not found"
response format across registries either.

**Privacy-redacted data**: registrant personal details are commonly
masked (`REDACTED FOR PRIVACY`) under GDPR-style privacy policies, but
this only affects registrant contact fields — this module never extracts
those. Registrar name and dates are essentially never redacted, so they
come through normally on privacy-protected domains.

## Output format

`lookup_domain()` always returns the same shape, whether the lookup
succeeded, found nothing, or failed at the network level:

```json
{
  "domain": "example.com",
  "registrar": "Registrar Corp Inc." ,
  "created": "1995-08-14T04:00:00Z",
  "updated": "2024-08-14T04:39:36Z",
  "expires": "2025-08-13T04:00:00Z",
  "status": ["clientTransferProhibited"],
  "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
  "raw": "Domain Name: EXAMPLE.COM\n...",
  "error": null,
  "not_found": false
}
```

- `error` is `None` on success, `not_found`, **and** on a legitimate
  "not registered" outcome — it's reserved for actual failures (network
  issues). `not_found: true` + `error: null` together mean "the lookup
  worked, the domain just isn't registered."
- On a network failure, every field except `domain` and `error` stays
  at its empty default (`None`/`[]`) — the shape never changes, callers
  never need to check for missing keys.
- `not_found` is one field beyond the originally specified 9
  (`domain/registrar/created/updated/expires/status/nameservers/raw/error`) —
  added because "not registered" and "an error occurred" are genuinely
  different outcomes a caller needs to distinguish, and folding one into
  the other would be misleading either way.

## Lab examples (used as test fixtures)

```
TEST CASE
──────────────
Input:    a Verisign-style raw response (.com)
Expected: registrar/created/updated/expires/status/nameservers all
          populated, not_found=False
```

```
TEST CASE
──────────────
Input:    "No match for domain "X.COM""
Expected: not_found=True, error=None, every other field empty
```

```
TEST CASE (masked data)
──────────────
Input:    a response with "Registrant Name: REDACTED FOR PRIVACY"
Expected: registrar/dates/nameservers still extracted normally —
          only registrant personal fields would be affected, and this
          module never extracts those
```

```
TEST CASE (timeout)
──────────────
Input:    a fake local server that accepts a connection but never replies
Expected: WhoisTimeoutError raised internally, surfaced as
          result["error"] containing "Timed out"
```

See `tests.py` for the full set (49 tests) and `test_fixtures.py` for
the raw sample responses.

## Flask integration

`whois_routes.py` (see the main app's route file) exposes:

- `GET /whois` — renders the page
- `POST /whois` — accepts `domain` (JSON or form), returns JSON (AJAX,
  detected via `X-Requested-With`) or a server-rendered page (no-JS
  fallback, matching the Port Scanner and DNS Lookup tools' pattern)

**Known limitation — blocking call**: `lookup_domain()` performs a
blocking socket call (up to ~10s by default) directly inside the Flask
request handler. Fine for a local, single-user tool; would tie up a
worker thread under real concurrent load in a production deployment.

## Tests

```bash
python -m unittest modules.whois.tests -v
```

49 tests, zero third-party dependencies (verified in a clean virtualenv
containing nothing but `pip`). Covers: domain validation (13 cases),
TLD/server resolution (6), real socket behavior against a local fake
WHOIS server — success, timeout, connection refused, DNS failure,
referral extraction (5 real-network tests, no internet required),
`lookup_domain_raw` composition via dependency injection — direct
response, referral followed, referral failure fallback, direct network
failure, validation-before-network (5), the parser against three
different real-world registry formats plus not-found/available/empty/
malformed/redacted variants (10), and the full `lookup_domain()`
assembly — valid domain, invalid domain (raises), nonexistent domain,
masked data, timeout, unexpected response, multiple TLDs, and
consistent result structure across every scenario (8).

## Requirements

No new dependencies. Uses only `socket`, `re`, `dataclasses` from the
standard library.