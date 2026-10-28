# Payload lists

One payload per line, in file order. Lines starting with `# ` (or a lone `#`)
are comments and are skipped by `fuzz.py`. Most payloads carry the marker
`FZcanary` so you can grep responses for reflection.

**Authorized testing only.** Point these at a target you own or are explicitly
allowed to test (your own authorized test environment), ideally a disposable
account/user. Everything here is a *detection marker*, not a working exploit —
by design nothing deletes data, changes state, or sends large payloads.

## Escalating pen-test tiers

Run them in order — each tier only widens scope on fields that "let you" in the
previous one.

| File | Tier | Size | What it's for |
|---|---|---|---|
| `pentest-1-smoke.txt` | 1 — smoke | ~13 | One benign probe per class: does *any* validation / output encoding run at all? Pure "would it let me." Cannot break anything. |
| `pentest-2-sample.txt` | 2 — sample | ~28 | ~10 vulnerability classes × 2–3 examples. Maps *which* classes a field is weak against. |
| `pentest-3-robust.txt` | 3 — robust | ~75 | Deep coverage + evasion variants, blind time-based (2s cap), NoSQL, JNDI, format strings, bounded oversize. Broadest "could I?" run that still changes nothing. |

### Safety rails baked into every tier
- **SQL:** `SELECT` / `OR` / `UNION SELECT NULL` and time delays capped at **2s**. No `DROP` / `DELETE` / `UPDATE` / `INSERT` / `xp_cmdshell`.
- **OS commands:** read-only only (`id`, `whoami`, `echo`) plus a 2s `sleep`.
- **SSRF / JNDI:** non-resolving canary hosts (`fzcanary.invalid`). The single cloud-metadata probe in tier 3 is marked **stop if it returns 200** — that's a critical finding to record, not a line to keep hammering.
- **Sizes:** bounded to ≤ ~1 KB. Nothing writes bulk data.

## Authorization & authentication lists

These target *access control*, not input handling. Fuzz the field named in each.

| File | Fuzz what | Finding looks like |
|---|---|---|
| `auth-tokens.txt` | the bearer **token value** | a non-valid token (garbage, alg:none, tampered role, expired, wrong-aud) returns **200 + real data** → broken authentication. |
| `forbidden-endpoints.txt` | the request **path**, using a **member** token | an admin/privileged path returns **200 + admin data** → BFLA. GET-only; method tampering is a separate manual test noted in the file. |
| `idor-ids.txt` | an org **id** in `GET /groups/org/{id}` | **200 with another org's data** → IDOR (placeholder ids — replace with real ones). |
| `idor-memberids.txt` | a member **id** in `POST /enrollments/search` | **200 with another member's records** → IDOR/BOLA (placeholder ids). |

## Other payload lists here

| File | What it's for |
|---|---|
| `probe-small.txt` | Original 30-line categorized quick probe. |
| `probe-medium.txt` | Original broader edge-case set. |

## How to read results
- **Reflected verbatim** → little/no output encoding (dig deeper).
- **Encoded / escaped** → output encoding applied (good).
- **400 / validation message** → input validation caught it (good).
- **500 / stack trace / ~2s delay** → input reached something fragile (bug / injection signal).
- **200, accepted, differs from baseline** → "it let me" — record it and escalate.

Always run `--dry-run` once first to confirm the URLs look right, and keep
concurrency low on shared environments.
