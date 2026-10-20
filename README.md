# LMS fuzz probe — small sample

## Folder layout
```
RaydasSniper\
├─ bin\         fuzz.py + launch-fuzzer.ps1 (the tool; desktop icon runs it)
├─ Requests\    Burp raw requests and Postman collections to fuzz
├─ payloads\    payload lists (probe-small.txt, idor-ids.txt)
├─ results\     CSV output, one per run
├─ bodies\      saved response bodies (bodies-<timestamp>\row-NNN.txt)
└─ README.md
```
`bin\` also holds `fuzzcore.py` (shared engine), `gui.py` (the window), and the build scripts.
`assets\` holds the logo and app icons.

## Three ways to run it
1. **Desktop app window (easiest).** Double-click the **LMS Fuzzer** desktop icon. A window opens:
   pick a request/collection, choose the request and field, pick a payload list, set options, Run.
   Results stream into a table; flagged rows (differs from baseline / raw reflection / 5xx) are
   highlighted. Buttons open the results CSV and bodies folder when it finishes.
2. **Packaged app for non-programmers (no Python needed).** See "Sharing" below.
3. **Command line.** From the project root:
   `python bin\fuzz.py --request Requests\<file> --payloads payloads\probe-small.txt --baseline --save-bodies`

Output always lands in `results\` (CSV) and `bodies\` (saved responses).

## Sharing / packaging (standalone app, no Python required)
- **Windows:** run `powershell -ExecutionPolicy Bypass -File bin\build-windows.ps1`. It produces
  `dist\LMSFuzzer\` containing `LMSFuzzer.exe` plus `Requests\ payloads\ results\ bodies\`. Zip that
  whole folder and share it — the recipient just unzips and double-clicks `LMSFuzzer.exe`.
- **Windows installer (Start-menu shortcut + uninstaller):** after the step above, compile
  `installer\LMSFuzzer.iss` with Inno Setup 6:
  `"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\LMSFuzzer.iss`
  (install Inno Setup once with `winget install JRSoftware.InnoSetup`). Output is
  `installer\Output\LMSFuzzer-Setup-<version>.exe` — a single setup .exe to share. It installs
  **per-user** into `%LocalAppData%\Programs\LMSFuzzer` (no admin prompt, and the app's `results\` /
  `bodies\` output folders stay writable there), adds an **LMS Fuzzer** Start-menu shortcut (desktop
  icon optional), and registers in **Add/Remove Programs** so it uninstalls cleanly. Rebuild the
  `dist\LMSFuzzer\` folder first whenever the tool changes, then recompile.
- **macOS:** must be built **on a Mac** (PyInstaller can't cross-build from Windows). On the Mac:
  `python3 -m pip install pyinstaller` then `bash bin/build-mac.sh` → `dist/LMSFuzzer.app`. First
  launch: right-click the app → Open (unsigned apps need that once).
- Both builds need PyInstaller installed on the build machine (`pip install pyinstaller`); the
  resulting app does not.

Purpose: a low-risk first pass to see **what validation is already applied** before any larger,
higher-risk run. These are short detection markers, not working exploits. Nothing here is designed
to delete data, write large payloads, or change state. Only use against a target you are authorized
to test (your own authorized test environment), ideally a disposable account/user.

The marker string `FZcanary` appears in most payloads so you can search responses for it:
- **Reflected verbatim** → little/no output encoding in that context (worth a deeper XSS/injection look).
- **Encoded** (`&lt;script&gt;`, `%3C`, etc.) → output encoding is being applied.
- **Rejected / 400 / validation message** → input validation is catching it.
- **500 / stack trace / long delay** → the input reached something that couldn't handle it — a bug signal.

## Line groups (one payload per line, in file order)

| Lines | Category | What a hit looks like |
|---|---|---|
| 1–3 | Baseline + quote breakouts | reflection; a bare `'` or `"` causing a 500 hints at injection |
| 4–6 | SQL injection (boolean, non-destructive) | different response for true vs false; DB error text |
| 7–9 | XSS contexts (HTML, attribute, URI) | `FZcanary` reflected unencoded |
| 10–12 | Template injection (Jinja/EL/Razor-style) | response contains `49` instead of the literal |
| 13–16 | Path traversal / encoding variants | file contents, different error, or path in a message |
| 17–20 | Command injection markers | `FZcanary` echoed, or a response-time change |
| 21–24 | Encoding / parser edge cases (null, CRLF, bad %, entity) | header injection, decode error, odd handling |
| 25–28 | Numeric boundaries | negative/zero/overflow accepted where it shouldn't be |
| 29 | Combined email + breakout | how a "typed" field handles mixed input |
| 30 | Leading/trailing whitespace | whether input is trimmed before validation |

## The fuzzer script (fuzz.py) — accepts Burp raw OR Postman

Double-click the **LMS Fuzzer** desktop icon, or run from this folder:

```
python bin\fuzz.py --request Requests\<file> --payloads payloads\probe-small.txt [--baseline]
```

`--request` can be:
- A **Burp raw request** (right-click a request in Burp > Copy to file). Type `FUZZ` where the
  payload goes, e.g. `status=FUZZ`.
- A **Postman collection** export (`*.postman_collection.json`). The tool lists the requests, you
  pick one, then pick which query/body field to fuzz — it inserts the marker for you. If a value in
  the collection already contains the literal `FUZZ`, that spot is used and no prompt appears.

Postman extras:
- `--env file.postman_environment.json` fills `{{variables}}` from an environment export.
- `--var token=eyJ...` sets or overrides a single `{{variable}}` (repeatable). A `bearer` auth token
  in the request (often `{{token}}`) becomes an `Authorization: Bearer ...` header.
- `--name 3` or `--name members` picks the request without prompting; `--param search` picks the field.

Output: a live table (status / length / time / reflection / payload) and a `results-<timestamp>.csv`
in this folder. Every CSV row includes the **full request URL** so you can replay anything in Burp
Repeater. Lines marked `<<<` differ from baseline, reflected raw, or returned 5xx — start there.

Always `--dry-run` once to confirm the URLs look right before sending for real.

### Saving response bodies
Add `--save-bodies` (checkbox in the launcher) to write each full response to a
`bodies-<timestamp>/row-NNN.txt` folder, and a 160-char snippet into the CSV's `body_snippet`
column. Use it to read what a 403 WAF page or a verbose 400 error actually says, without re-sending.

### IDOR / authorization testing (idor-ids.txt)
`idor-ids.txt` is a payload list of org ids for the `GET /groups/org/{id}` endpoint. Run it the same
way (fuzz the `[path]` id). Read the result as:
- **403 / 401** → authorization enforced (good).
- **404** → that id doesn't exist (inconclusive — try other ids).
- **200 with another org's data** → **IDOR finding**: record it and stop.

The ids in that file are **placeholders** — replace them with one id you own (control, expect 200)
and several ids from a *different* account for a conclusive test. Lines starting with `# ` (or a
lone `#`) are comments. Run with `--save-bodies` so you can confirm what any 200 actually returned.

## Running (Burp Intruder)
- Mark one insertion point at a time (Sniper), load this file as the payload list.
- Turn **off** payload URL-encoding first to see raw handling, then repeat **with** it on — the
  difference tells you where decoding happens.
- Sort results by status code and response length to spot the outliers quickly.
- Keep concurrency low on a shared environment so you don't distort it for other testers.

## Notes / safety
- Only ~30 payloads, so this stays well within rate and storage limits.
- Avoid pointing the **stored** fields (course/group names, profile) at a shared tenant until you've
  confirmed you can clean them up — reflected/GET params are safer for a first look.
- Record which field and endpoint each run targeted; the follow-up ("bigger risk") file should only
  expand the categories that showed weak or no validation here.
