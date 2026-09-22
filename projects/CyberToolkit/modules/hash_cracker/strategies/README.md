# Hash Cracker

A standalone hash identification and recovery module for CyberToolkit.
No dependency on Flask, HTML, or any web framework — every file under
`modules/hash_cracker/` can be imported and used from a plain Python
script, a test suite, or a web app alike.

## What this actually does — and doesn't

A hash cannot be "decrypted." Hashing has no mathematical inverse. What
this module does instead:

1. **Identify** the likely algorithm(s) behind a hash from its length,
   character set, and structural format (e.g. bcrypt's `$2b$` prefix).
2. **Attempt recovery** by generating candidate plaintexts, hashing each
   one, and comparing the result to the target — using one of three
   strategies (below). If a candidate's hash matches, that candidate
   *is* the original value (or a collision, astronomically unlikely for
   the algorithms and lengths this tool handles).

If nothing matches, the tool reports `not_found` — that's a legitimate,
expected outcome, not a failure of the tool.

## Architecture

```
modules/hash_cracker/
├── __init__.py
├── models.py             # typed reference shapes (JobStatus enum, dict shapes)
├── analyzer.py           # hash format identification (length, charset, prefixes)
├── validators.py         # input validation, no side effects
├── algorithms.py         # hashlib wrappers (plain + salted)
├── candidates.py         # generators: dictionary lines, brute-force strings
├── rainbow_table.py      # real rainbow table: chain generation + search
├── engine.py             # Job / RainbowJob / Engine — threading, control, benchmark
├── tests.py              # unit tests, no Flask required
└── strategies/
    ├── __init__.py
    ├── dictionary.py     # wordlist + optional transformations
    ├── brute_force.py    # exhaustive generation over a charset/length range
    └── rainbow.py        # compatibility check only (salt/structured formats)
```

**Layering rule**: `analyzer.py`, `validators.py`, `algorithms.py`,
`candidates.py`, and `rainbow_table.py` are pure functions with no shared
state. `engine.py` is the only file that manages threads, state, and
control (pause/resume/stop) — it imports `JobStatus` from `models.py`
rather than redefining it, so there's a single source of truth for job
states. Flask (in the main app, see `hash_cracker_routes.py`) only ever
calls `engine.py` functions and renders their return values — it
contains no cracking logic itself.

## Algorithms supported

Raw digest comparison via `hashlib`: **MD5, SHA1, SHA224, SHA256, SHA384,
SHA512**.

Identified but **not** crackable through this module's raw-hash path:
bcrypt (`$2a$`/`$2b$`/`$2y$`), MD5-crypt (`$1$`), SHA256-crypt (`$5$`),
SHA512-crypt (`$6$`). These need their own comparison function (e.g.
`bcrypt.checkpw`) rather than `hashlib` digest equality — out of scope
for the current version. `analyzer.py` still identifies them correctly
and reports `crackable_locally: false`.

`MD5` and `NTLM` share the same digest length (32 hex chars) and are
reported as ambiguous alternatives — the tool doesn't guess between them.

## Strategies

### Dictionary
Reads candidates from a wordlist file line by line (`candidates.iter_dictionary`)
— never loads the whole file into memory, so a multi-GB wordlist costs
the same RAM as a 4KB one. Optional transformations (`capitalize`, `upper`,
`append_1`, `append_123`, `leet`) generate variants of each word inline.

### Brute Force
Exhaustively generates every string over a chosen character set
(`itertools.product`), for lengths in a `[min_len, max_len]` range.

**Length range rule**: the *spread* (`max_len - min_len`) must be ≤ 8 —
not the absolute length. Searching lengths 10–11 (spread=1) is cheap;
searching 1–15 (spread=14) is rejected regardless of how short the
individual lengths are. A hard technical ceiling of 24 also applies to
`max_len` itself, independent of spread.

**Feasibility check**: before starting, `Engine.estimate()` runs an
invisible mini-benchmark (~20,000 hashes) *on the machine actually
running the tool*, and projects a real time estimate — not a hard-coded
guess. If the estimate exceeds 24 hours (`DEFAULT_HARD_CAP_SECONDS`), the
API refuses to start unless the caller explicitly passes `"confirmed":
true`, after seeing the number.

### Rainbow Table
A **real** implementation using precomputed hash chains with
per-position reduction functions — not brute force relabeled. See
`rainbow_table.py` for the full algorithm description. In short: a chain
starts from a random plaintext, alternates hashing and reducing for
`chain_length` steps, and only the start/endpoint pair is stored. Lookup
works backward from the target hash, trying each possible chain position.

**Compatibility**: incompatible with salted hashes and structured formats
(bcrypt/crypt) — a table built for one salt is useless against another.
`strategies/rainbow.is_compatible()` checks this before offering the
option.

**Coverage is probabilistic**, exactly like a real rainbow table. A table
covering a fraction of the search space will legitimately report
`not_found` for candidates outside that fraction — this is expected
behavior, not a bug. Empirically verified in testing: a table with
theoretical ~11% coverage found ~11% of random samples.

**Resource limits**: `table_size` ≤ 200,000 and `chain_length` ≤ 2,000
(server-enforced, independent of any time estimate). With these caps,
the worst possible case finishes in a few minutes — the 24h confirmation
flow exists but is essentially unreachable for rainbow given these
limits; it remains meaningful for brute force, where the user controls
`min_len`/`max_len` directly.

### Automatic (frontend-level, not a distinct backend strategy)
Tries the built-in dictionary first, then falls back to a short brute
force (lowercase + numbers, 1–4 chars) if nothing is found. Implemented
as a sequential client-side pipeline over the same `dictionary` and
`brute_force` endpoints — each step is logged as it runs. Uses a fixed,
guaranteed-present wordlist filename rather than reading the UI's
wordlist dropdown, to avoid a load-order race.

## Salted hashes (lab format)

For `dictionary` and `brute_force` (not `rainbow`, which is
incompatible with salts by definition), a salt can be supplied:

```json
{ "hash_value": "...", "salt": "a1b2c3", "salt_order": "suffix" }
```

- `salt_order: "suffix"` → `hash(candidate + salt)`
- `salt_order: "prefix"` → `hash(salt + candidate)`

## Input format

All `start_*` and `estimate` endpoints take JSON. Common fields:

| Field | Type | Notes |
|---|---|---|
| `hash_value` | string | required, hex (or `hash:salt`, or a structured prefix like `$2b$...`) |
| `algorithm` | string | one of `MD5`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512` |
| `salt` / `salt_order` | string | optional, dictionary/brute_force only |

Strategy-specific fields:

- **dictionary**: `wordlist` (filename in the server's `wordlists/` directory — never an arbitrary path), `transformations` (array)
- **brute_force**: `lowercase`/`uppercase`/`numbers`/`symbols` (bool), `min_length`, `max_length`, `confirmed` (bool, only needed if a prior call returned `requires_confirmation`)
- **rainbow**: same charset flags, `length` (single fixed value, not a range), optional `table_size`/`chain_length` (server picks sane defaults and clamps to hard limits), `confirmed`

## Output format

`analyze()` returns:

```json
{
  "input": "...", "length": 32, "charset_used": ["0","1",...],
  "is_hex": true, "format": "hex", "prefix": null, "structured": false,
  "salt_format": null, "possible_algorithms": ["MD5", "NTLM"],
  "crackable_locally": true
}
```

A job `snapshot()` (polled via `GET /jobs/<id>/status`) returns:

```json
{
  "job_id": "job-3", "status": "running", "algorithm": "MD5",
  "strategy": "brute_force", "phase": null,
  "candidates_tested": 128401, "speed": 82431.2, "elapsed": 3.47,
  "progress": 68.2, "estimated_seconds": 5.1,
  "found_candidate": null, "error": null
}
```

`status` is one of: `idle`, `running`, `paused`, `completed`, `not_found`,
`stopped`, `error`. `phase` is only set for rainbow jobs (`"building"` or
`"searching"`); `null` otherwise.

## Lab examples (known test cases)

These are also used as fixtures in `tests.py` (`KNOWN_HASHES`):

```
TEST CASE
──────────────
Algorithm:       MD5
Known candidate: password
Hash:            5f4dcc3b5aa765d61d8327deb882cf99
Expected:        FOUND (dictionary, using the shipped wordlists/passwords.txt)
```

```
TEST CASE
──────────────
Algorithm:       SHA1
Known candidate: password
Hash:            5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
Expected:        FOUND (dictionary)
```

```
TEST CASE
──────────────
Algorithm:       SHA256
Known candidate: password
Hash:            5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d
Expected:        FOUND (dictionary)
```

```
TEST CASE (salted)
──────────────
Algorithm:       MD5
Known candidate: password
Salt:            PEPPER  (order: suffix)
Hash:            md5("passwordPEPPER")
Expected:        FOUND (dictionary, salt enabled)
```

```
TEST CASE (rainbow, small space — reliable demo)
──────────────
Algorithm:       MD5
Charset:         lowercase only
Length:          3
Known candidate: cab
Expected:        FOUND (rainbow, table_size≥2000 chain_length≥100 over a 17,576-candidate space)
```

## Known limitations

- **Structured formats not crackable**: bcrypt/crypt hashes are identified
  but not attacked — they need per-format comparison logic, not raw digest
  equality.
- **Rainbow table is demo-scale**: thousands of chains, not a production
  rockyou-scale precomputed table. Coverage is a deliberate, disclosed
  trade-off, not a bug.
- **Pause/stop checkpoint granularity, not instant**: `pause()`/`stop()`
  are cooperative and checked at loop boundaries, not truly instantaneous.
  For `Job` (dictionary/brute force), that boundary is *one candidate* —
  a single in-flight candidate can still complete just after the status
  flips to `paused`. For `RainbowJob`, the boundary is *one full chain*
  during the build phase — up to one `chain_length`'s worth of extra hash
  operations can land after `pause()` is called, while the in-flight
  chain finishes. This was caught empirically while writing `tests.py`
  (an assertion expecting an instant freeze was flaky); the tests now
  account for this by waiting out the current unit of work before
  treating the counter as settled. Not a bug — a documented trade-off
  of cooperative, checkpoint-based control instead of hard preemption.
- **Dictionary has no progress percentage**: counting a wordlist's lines
  ahead of time costs a full read pass; the tool shows an honestly
  labeled indeterminate progress bar instead of a fake percentage.
- **In-memory job registry**: jobs live in `Engine._jobs`, lost on process
  restart. Fine for a local single-user tool, not for multi-worker
  deployments.
- **No distributed cracking**: everything runs single-machine, single-process
  (multi-threaded, not multi-process) — by design, for a local toolkit.
- **Wordlist uploads capped at 5MB** and restricted to `.txt` files, saved
  under a server-controlled directory only (`werkzeug.secure_filename` +
  basename check — no arbitrary path traversal).
- **Frontend requires JavaScript**, with no server-rendered fallback —
  unlike the port scanner and DNS lookup tools, live progress/pause/stop
  only make sense running client-side against the polling API.

## Tests

Run without Flask, without a browser:

```bash
python -m unittest modules.hash_cracker.tests -v
```

61 tests, covering: algorithm correctness (plain + salted, prefix/suffix),
every validator (including the spread-vs-absolute-length distinction and
path-traversal rejection on wordlist names), analyzer edge cases
(MD5/NTLM ambiguity, bcrypt detection, hash:salt convention), candidate
generators (order, charset, length respect), strategy wiring
(transformations, rainbow compatibility), and the full engine for both
job types: dictionary/brute-force match & not_found, pause holding
progress (accounting for checkpoint granularity), resume continuing,
stop terminating cleanly, unsupported algorithm and missing wordlist
producing a clean `error` status instead of crashing, benchmark/estimate
sanity — plus rainbow-specific tests (deterministic chain-hit via a
seeded table, phase transitions building→searching, pause/resume/stop
during table build, clean not_found on a tiny table).

## Server-side wiring (Flask)

`hash_cracker_routes.py` contains the full set of routes as they should
be merged into your main `app.py`:

- `GET /hash-cracker` — renders the page
- `POST /api/hash-cracker/analyze`
- `GET /api/hash-cracker/wordlists`, `POST /api/hash-cracker/wordlists/upload`
- `POST /api/hash-cracker/estimate`
- `POST /api/hash-cracker/start/dictionary`, `/start/brute_force`, `/start/rainbow`
- `GET /api/hash-cracker/jobs/<id>/status`, `POST .../pause`, `.../resume`, `.../stop`

It assumes `templates/hash_cracker.html`, `static/js/hash_cracker.js`,
and `static/css/hash_cracker.css` are in place, and that `static/css/base.css`
+ `static/css/components.css` + `static/js/base.js` (shared across the
whole CyberToolkit site, not specific to this module) are already loaded
via `base.html`. `base.js`'s `apiRequest()` must attach the full response
body to thrown errors as `err.payload` — the version shipped alongside
this bundle already does.