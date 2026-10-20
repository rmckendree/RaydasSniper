#!/usr/bin/env python3
"""
Simple Sniper-style fuzzer for AUTHORIZED security testing of your own APIs.

Input can be EITHER:
  * a Burp "Copy to file" raw request (put the word FUZZ where the payload goes), OR
  * a Postman collection export (*.postman_collection.json). The tool lists the
    requests, you pick one, then pick which query/body field to fuzz (or it uses a
    literal FUZZ if you already placed one).

For each payload it swaps it into the one marked spot, sends the request, and records
status, length, time, reflection, and the full URL. It does NOT escalate, retry, or do
anything destructive — it reports, you decide. Like Burp Intruder > Sniper, on the CLI.

Usage:
  python fuzz.py --request req.txt --payloads probe-small.txt
  python fuzz.py --request api.postman_collection.json --payloads probe-small.txt
                 [--env prod.postman_environment.json] [--var token=eyJ...] [--name 3]

Key options:
  --scheme https|http   URL scheme when the source omits it. Default: https.
  --env FILE            Postman environment export; its values fill {{variables}}.
  --var k=v             Set/override a {{variable}} (repeatable), e.g. --var token=eyJ...
  --name N|text         Pick the Postman request by number or name substring (skips the prompt).
  --param NAME          Fuzz this query/body field (skips the prompt); inserts FUZZ for you.
  --delay 0.3           Seconds between requests (be gentle on shared envs).
  --timeout 20          Per-request timeout.
  --canary FZcanary     Marker to look for in responses (raw vs encoded reflection).
  --baseline            Send one un-fuzzed request first, flag big differences.
  --insecure            Skip TLS cert verification (self-signed test envs).
  --dry-run             Print what WOULD be sent, send nothing.
  --out results.csv     CSV path (default: results-<timestamp>.csv next to this script).
"""
import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request

MARKER = "FUZZ"


# --------------------------- Burp raw request ---------------------------

def parse_raw_request(text):
    text = text.replace("\r\n", "\n")
    head, body = (text.split("\n\n", 1) + [""])[:2] if "\n\n" in text else (text, "")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("Request file is empty or has no request line.")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"First line is not a valid request line: {lines[0]!r}")
    method, path = parts[0], parts[1]
    headers = {}
    for line in lines[1:]:
        if ":" in line and line.strip():
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return method, path, headers, body, None  # no scheme override


# --------------------------- Postman collection ---------------------------

def _subst(value, variables):
    """Replace {{var}} with known values; leave unknown ones and collect them."""
    if not isinstance(value, str):
        return value, set()
    missing = set()

    def repl(m):
        key = m.group(1).strip()
        if key in variables and variables[key] != "":
            return str(variables[key])
        missing.add(key)
        return m.group(0)

    return re.sub(r"\{\{([^}]+)\}\}", repl, value), missing


def _collect_variables(collection, env_obj, overrides):
    variables = {}
    for v in (collection.get("variable") or []):
        if "key" in v:
            variables[v["key"]] = v.get("value", "")
    if env_obj:
        for v in (env_obj.get("values") or []):
            if v.get("enabled", True) and "key" in v:
                variables[v["key"]] = v.get("value", "")
    variables.update(overrides)
    return variables


def _flatten(items, trail=""):
    out = []
    for it in items or []:
        name = it.get("name", "")
        full = f"{trail} / {name}".strip(" /") if trail else name
        if "item" in it:
            out.extend(_flatten(it["item"], full))
        elif "request" in it:
            out.append((full, it["request"]))
    return out


def _url_parts(url, variables):
    """Return (scheme, host, path, [(qkey, qval, enabled)]) from a Postman url field."""
    if isinstance(url, str):
        raw, _ = _subst(url, variables)
        p = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
        q = [(k, v, True) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)]
        return (p.scheme or "https"), p.netloc, (p.path or "/"), q
    # object form
    proto = (url.get("protocol") or "https")
    host = url.get("host") or []
    host = ".".join(host) if isinstance(host, list) else str(host)
    port = url.get("port")
    if port:
        host = f"{host}:{port}"
    path = url.get("path") or []
    path = "/" + "/".join(str(s) for s in path) if isinstance(path, list) else str(path)
    host, _ = _subst(host, variables)
    path, _ = _subst(path, variables)
    # A variable like {{baseUrl}} may already carry a scheme (and even a path); unwrap it.
    if "://" in host:
        sp = urllib.parse.urlsplit(host)
        proto = sp.scheme or proto
        host = sp.netloc
        if sp.path and sp.path != "/":
            path = sp.path.rstrip("/") + path
    query = []
    for q in (url.get("query") or []):
        if q.get("disabled"):
            continue
        k, _ = _subst(q.get("key", ""), variables)
        v, _ = _subst(q.get("value", ""), variables)
        query.append((k, v, True))
    return proto, host, path, query


def load_postman(path, env_obj, overrides, pick_name, pick_param):
    with open(path, "r", encoding="utf-8") as f:
        collection = json.load(f)
    variables = _collect_variables(collection, env_obj, overrides)
    reqs = _flatten(collection.get("item"))
    if not reqs:
        raise ValueError("No requests found in that Postman collection.")

    # Choose request
    idx = None
    if pick_name:
        if pick_name.isdigit() and 1 <= int(pick_name) <= len(reqs):
            idx = int(pick_name) - 1
        else:
            for i, (name, _) in enumerate(reqs):
                if pick_name.lower() in name.lower():
                    idx = i
                    break
    if idx is None:
        print("\nRequests in this collection:")
        for i, (name, rq) in enumerate(reqs, 1):
            method = rq.get("method", "GET")
            print(f"  {i:>2}. {method:<6} {name}")
        sel = input("\nPick a request number: ").strip()
        if not sel.isdigit() or not (1 <= int(sel) <= len(reqs)):
            raise SystemExit("No valid request chosen.")
        idx = int(sel) - 1

    name, rq = reqs[idx]
    method = rq.get("method", "GET")
    scheme, host, path, query = _url_parts(rq.get("url", ""), variables)

    # Headers
    headers = {}
    for h in (rq.get("header") or []):
        if h.get("disabled"):
            continue
        hk, _ = _subst(h.get("key", ""), variables)
        hv, _ = _subst(h.get("value", ""), variables)
        if hk:
            headers[hk] = hv
    headers.setdefault("Host", host)

    # Auth -> Authorization header (bearer is the common case)
    auth = rq.get("auth") or collection.get("auth")
    if auth and auth.get("type") == "bearer" and "Authorization" not in headers:
        tok = ""
        for t in (auth.get("bearer") or []):
            if t.get("key") == "token":
                tok, _ = _subst(t.get("value", ""), variables)
        if tok:
            headers["Authorization"] = f"Bearer {tok}"

    # Body
    body = ""
    body_fields = []  # (kind, key)
    b = rq.get("body") or {}
    mode = b.get("mode")
    if mode == "raw":
        body, _ = _subst(b.get("raw", ""), variables)
    elif mode == "urlencoded":
        pairs = []
        for kv in (b.get("urlencoded") or []):
            if kv.get("disabled"):
                continue
            k, _ = _subst(kv.get("key", ""), variables)
            v, _ = _subst(kv.get("value", ""), variables)
            pairs.append([k, v])
            body_fields.append(("body", k))
        body = urllib.parse.urlencode(pairs)
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    # Where can we fuzz? literal FUZZ already present wins.
    blob = path + "|" + body + "|" + "|".join(headers.values())
    if MARKER in blob:
        qs = urllib.parse.urlencode([(k, v) for k, v, _ in query]) if query else ""
        full_path = path + ("?" + qs if qs else "")
        # if FUZZ is in a query value it's already in path via raw; rebuild to be safe
        if query and MARKER in qs:
            full_path = path + "?" + qs
        return method, _with_query(path, query), headers, body, scheme

    path_segs = [s for s in path.split("/") if s]
    fuzzable = [("path", s) for s in path_segs] + [("query", k) for k, _, _ in query] + body_fields
    if not fuzzable:
        raise SystemExit(
            f"Request '{name}' has no query/body fields to fuzz, and no literal {MARKER}.\n"
            f"Add {MARKER} into a value in the collection, or pick a different request.")

    # Choose the field to fuzz
    chosen = None
    if pick_param:
        for kind, key in fuzzable:
            if key == pick_param:
                chosen = (kind, key)
                break
        if not chosen:
            raise SystemExit(f"--param {pick_param!r} not found. Options: "
                             + ", ".join(k for _, k in fuzzable))
    if not chosen:
        print(f"\nFuzzable fields in '{name}':")
        for i, (kind, key) in enumerate(fuzzable, 1):
            print(f"  {i:>2}. [{kind}] {key}")
        sel = input("\nPick a field to fuzz: ").strip()
        if not sel.isdigit() or not (1 <= int(sel) <= len(fuzzable)):
            raise SystemExit("No valid field chosen.")
        chosen = fuzzable[int(sel) - 1]

    kind, key = chosen
    if kind == "path":
        # Replace the chosen path segment with the marker (first match).
        segs = path.split("/")
        for i, s in enumerate(segs):
            if s == key:
                segs[i] = MARKER
                break
        path = "/".join(segs)
    elif kind == "query":
        query = [(k, (MARKER if k == key else v), e) for k, v, e in query]
    else:  # body (urlencoded)
        pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
        body = urllib.parse.urlencode([(k, (MARKER if k == key else v)) for k, v in pairs],
                                      safe=MARKER)
    print(f"\nFuzzing [{kind}] {key} in '{name}'.")
    return method, _with_query(path, query), headers, body, scheme


def _with_query(path, query):
    if not query:
        return path
    qs = urllib.parse.urlencode([(k, v) for k, v, _ in query], safe=MARKER)
    return path + "?" + qs


# --------------------------- shared send/report ---------------------------

def build_url(scheme, headers, path):
    host = headers.get("Host") or headers.get("host")
    if not host:
        raise ValueError("No Host header found.")
    return f"{scheme}://{host}{path}"


def count_marker(path, headers, body):
    return (path + "|".join(headers.values()) + body).count(MARKER)


def apply_payload(path, headers, body, payload):
    """Insert the payload, percent-encoding it in URL/body contexts (headers stay raw)."""
    enc = urllib.parse.quote(payload, safe="")
    if "?" in path:
        p, q = path.split("?", 1)
        new_path = p.replace(MARKER, enc) + "?" + q.replace(MARKER, enc)
    else:
        new_path = path.replace(MARKER, enc)
    return (new_path,
            {k: v.replace(MARKER, payload) for k, v in headers.items()},
            body.replace(MARKER, enc))


def reflection_kind(body_text, payload, canary):
    if canary and canary in body_text:
        raw_markers = ["<script", "onerror=", "'", '"', "../", "49"]
        if any(m in payload and m in body_text for m in raw_markers):
            return "RAW (unencoded)"
        return "reflected"
    if canary and (html.escape(canary) in body_text or urllib.parse.quote(canary) in body_text):
        return "encoded"
    if payload and payload in body_text:
        return "payload-reflected"
    return ""


def send(url, method, headers, body, timeout, insecure):
    data = body.encode("utf-8") if body else None
    # Drop Content-Length (urllib sets it) and Accept-Encoding (so responses come back
    # uncompressed and readable — otherwise lengths/reflection run on gzip bytes).
    _skip = {"content-length", "accept-encoding"}
    send_headers = {k: v for k, v in headers.items() if k.lower() not in _skip}
    req = urllib.request.Request(url, data=data, headers=send_headers, method=method)
    ctx = None
    if url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
            return resp.status, len(raw), time.time() - start, raw.decode("utf-8", "replace"), ""
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        return e.code, len(raw), time.time() - start, raw.decode("utf-8", "replace"), ""
    except Exception as e:
        return "ERR", 0, time.time() - start, "", f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser(description="Simple Sniper-style API fuzzer (authorized testing only).")
    ap.add_argument("--request", required=True, help="Burp raw file OR *.postman_collection.json")
    ap.add_argument("--payloads", required=True)
    ap.add_argument("--scheme", default="https", choices=["https", "http"])
    ap.add_argument("--env", default="", help="Postman environment export (fills {{variables}})")
    ap.add_argument("--var", action="append", default=[], help="Override a variable, k=v (repeatable)")
    ap.add_argument("--name", default="", help="Pick Postman request by number or name substring")
    ap.add_argument("--param", default="", help="Field to fuzz (skips the prompt)")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--canary", default="FZcanary")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--save-bodies", action="store_true",
                    help="Write each response body to a bodies-<timestamp>/ folder and log a snippet.")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    overrides = {}
    for pair in args.var:
        if "=" in pair:
            k, v = pair.split("=", 1)
            overrides[k.strip()] = v

    is_postman = args.request.lower().endswith(".json")
    scheme_override = None
    if is_postman:
        env_obj = None
        if args.env:
            with open(args.env, "r", encoding="utf-8") as f:
                env_obj = json.load(f)
        method, path, headers, body, scheme_override = load_postman(
            args.request, env_obj, overrides, args.name, args.param)
    else:
        with open(args.request, "r", encoding="utf-8") as f:
            method, path, headers, body, scheme_override = parse_raw_request(f.read())

    scheme = scheme_override or args.scheme

    if count_marker(path, headers, body) == 0:
        sys.exit(f"ERROR: no {MARKER} marker to fuzz. For a raw file, add {MARKER} by hand.")

    with open(args.payloads, "r", encoding="utf-8") as f:
        # Skip blank lines and comment lines ("# ..." or a lone "#").
        # Note: "#{7*7}" is a real payload, not a comment.
        payloads = [line.rstrip("\n") for line in f
                    if line.strip() != ""
                    and line.strip() != "#"
                    and not line.lstrip().startswith("# ")]

    base_url = build_url(scheme, headers, path)
    print(f"\nTarget : {method} {base_url}")
    print(f"Payloads: {len(payloads)} from {os.path.basename(args.payloads)}")
    print(f"Mode   : {'DRY RUN (nothing sent)' if args.dry_run else 'live'}  "
          f"delay={args.delay}s timeout={args.timeout}s\n")

    stamp = f"{dt.datetime.now():%Y%m%d-%H%M%S}"
    # Project root is the parent of bin/ (where this script lives).
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    results_dir = os.path.join(root, "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = args.out or os.path.join(results_dir, f"results-{stamp}.csv")
    bodies_dir = ""
    if args.save_bodies and not args.dry_run:
        bodies_dir = os.path.join(root, "bodies", f"bodies-{stamp}")
        os.makedirs(bodies_dir, exist_ok=True)

    rows = []
    base_len = base_status = None
    if args.baseline and not args.dry_run:
        bp, bh, bb = apply_payload(path, headers, body, args.canary)
        base_status, base_len, _, _, _ = send(build_url(scheme, bh, bp), method, bh, bb,
                                               args.timeout, args.insecure)
        print(f"baseline: status={base_status} length={base_len}\n")

    header = f"{'#':>3}  {'status':>6}  {'length':>8}  {'time':>6}  {'reflection':<16}  payload"
    print(header)
    print("-" * len(header))

    for i, payload in enumerate(payloads, 1):
        pp, ph, pb = apply_payload(path, headers, body, payload)
        url = build_url(scheme, ph, pp)
        disp = payload if len(payload) <= 45 else payload[:42] + "..."
        if args.dry_run:
            print(f"{i:>3}  {'--':>6}  {'--':>8}  {'--':>6}  {'--':<16}  {disp}")
            rows.append({"n": i, "status": "", "length": "", "time_s": "", "reflection": "",
                         "diff": "", "url": url, "payload": payload, "error": ""})
            continue
        status, length, elapsed, text, err = send(url, method, ph, pb, args.timeout, args.insecure)
        refl = reflection_kind(text, payload, args.canary)
        snippet = ""
        if bodies_dir and text:
            with open(os.path.join(bodies_dir, f"row-{i:03d}.txt"), "w", encoding="utf-8") as bf:
                bf.write(text)
            snippet = " ".join(text.split())[:160]
        diff = ""
        if base_len is not None and isinstance(status, int):
            if status != base_status:
                diff = "status!"
            elif abs(length - base_len) > max(50, int(0.1 * base_len)):
                diff = "len!"
        flag = " <<<" if (diff or "RAW" in refl or (isinstance(status, int) and status >= 500)) else ""
        print(f"{i:>3}  {str(status):>6}  {str(length):>8}  {elapsed:>6.2f}  {refl:<16}  {disp}{flag}")
        rows.append({"n": i, "status": status, "length": length, "time_s": f"{elapsed:.3f}",
                     "reflection": refl, "diff": diff, "url": url, "payload": payload,
                     "body_snippet": snippet, "error": err})
        time.sleep(args.delay)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["n", "status", "length", "time_s", "reflection",
                                          "diff", "url", "payload", "body_snippet", "error"])
        w.writeheader()
        w.writerows(rows)

    print(f"\nSaved {len(rows)} rows to:\n  {out_path}")
    if bodies_dir:
        print(f"Response bodies saved in:\n  {bodies_dir}  (one row-NNN.txt per request)")
    print("Lines marked <<< differ from baseline, reflected raw, or returned 5xx — look at those first.")


if __name__ == "__main__":
    main()
