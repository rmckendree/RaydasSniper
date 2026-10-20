#!/usr/bin/env python3
"""
Engine for the LMS fuzz tool (authorized security testing only).

Pure standard library. Imported by both the CLI (fuzz.py) and the GUI (gui.py).
Parses a Burp raw request OR a Postman collection, lets the caller choose a request
and a single field to fuzz, then sends one request per payload and yields results.
Nothing here escalates, retries, or acts destructively — it reports.
"""
import csv
import datetime as dt
import html
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

MARKER = "FUZZ"


# ----------------------------- project paths -----------------------------
# Works both as plain scripts and when packaged by PyInstaller.
#   data_root()    -> writable folder holding payloads/Requests/results/bodies
#                     (project root in dev; the folder next to the .exe/.app when frozen)
#   resource_dir() -> read-only bundle holding assets/ (project root in dev; sys._MEIPASS frozen)

def _frozen():
    return getattr(sys, "frozen", False)


def data_root():
    if _frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_dir():
    if _frozen():
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def project_root():  # backwards-compatible alias (dev layout)
    return data_root()


def results_dir():
    d = os.path.join(data_root(), "results")
    os.makedirs(d, exist_ok=True)
    return d


def bodies_root():
    d = os.path.join(data_root(), "bodies")
    os.makedirs(d, exist_ok=True)
    return d


# ----------------------------- Burp raw request -----------------------------

def parse_raw_request(text):
    """-> dict(source='raw', method, path, headers, body, scheme=None, fuzzable=[], ...)."""
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
    has_marker = MARKER in (path + "|".join(headers.values()) + body)
    return {"source": "raw", "name": f"{method} {path}", "method": method, "path": path,
            "headers": headers, "body": body, "scheme": None, "has_marker": has_marker}


# ----------------------------- Postman collection -----------------------------

def _subst(value, variables):
    if not isinstance(value, str):
        return value
    import re
    return re.sub(r"\{\{([^}]+)\}\}",
                  lambda m: str(variables.get(m.group(1).strip(), m.group(0)))
                  if variables.get(m.group(1).strip(), "") != "" else m.group(0),
                  value)


def collect_variables(collection, env_obj, overrides):
    variables = {}
    for v in (collection.get("variable") or []):
        if "key" in v:
            variables[v["key"]] = v.get("value", "")
    if env_obj:
        for v in (env_obj.get("values") or []):
            if v.get("enabled", True) and "key" in v:
                variables[v["key"]] = v.get("value", "")
    variables.update(overrides or {})
    return variables


def flatten_items(items, trail=""):
    out = []
    for it in items or []:
        name = it.get("name", "")
        full = f"{trail} / {name}".strip(" /") if trail else name
        if "item" in it:
            out.extend(flatten_items(it["item"], full))
        elif "request" in it:
            out.append((full, it["request"]))
    return out


def _url_parts(url, variables):
    if isinstance(url, str):
        raw = _subst(url, variables)
        p = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
        q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)]
        return (p.scheme or "https"), p.netloc, (p.path or "/"), q
    proto = url.get("protocol") or "https"
    host = url.get("host") or []
    host = ".".join(host) if isinstance(host, list) else str(host)
    if url.get("port"):
        host = f"{host}:{url['port']}"
    path = url.get("path") or []
    path = "/" + "/".join(str(s) for s in path) if isinstance(path, list) else str(path)
    host = _subst(host, variables)
    path = _subst(path, variables)
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
        query.append((_subst(q.get("key", ""), variables), _subst(q.get("value", ""), variables)))
    return proto, host, path, query


def load_collection(path, env_obj=None, overrides=None):
    with open(path, "r", encoding="utf-8") as f:
        collection = json.load(f)
    variables = collect_variables(collection, env_obj, overrides)
    reqs = flatten_items(collection.get("item"))
    if not reqs:
        raise ValueError("No requests found in that Postman collection.")
    return collection, variables, reqs


def request_target(request, variables, collection=None):
    """Resolve a Postman request into method/path/headers/body/scheme + fuzzable field list."""
    method = request.get("method", "GET")
    scheme, host, path, query = _url_parts(request.get("url", ""), variables)
    headers = {}
    for h in (request.get("header") or []):
        if h.get("disabled"):
            continue
        hk = _subst(h.get("key", ""), variables)
        if hk:
            headers[hk] = _subst(h.get("value", ""), variables)
    headers.setdefault("Host", host)
    auth = request.get("auth") or (collection.get("auth") if collection else None)
    if auth and auth.get("type") == "bearer" and "Authorization" not in headers:
        tok = ""
        for t in (auth.get("bearer") or []):
            if t.get("key") == "token":
                tok = _subst(t.get("value", ""), variables)
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
    body, body_fields = "", []
    json_obj = None
    json_paths = {}   # label -> (pathlist, is_array)
    b = request.get("body") or {}
    if b.get("mode") == "raw":
        body = _subst(b.get("raw", ""), variables)
        try:
            json_obj = json.loads(body)
            json_paths = _json_leaves(json_obj)
            for label in json_paths:
                body_fields.append(("json", label))
            headers.setdefault("Content-Type", "application/json")
        except Exception:
            json_obj = None  # not JSON; leave body as a raw blob
    elif b.get("mode") == "urlencoded":
        pairs = []
        for kv in (b.get("urlencoded") or []):
            if kv.get("disabled"):
                continue
            k = _subst(kv.get("key", ""), variables)
            pairs.append([k, _subst(kv.get("value", ""), variables)])
            body_fields.append(("form", k))
        body = urllib.parse.urlencode(pairs)
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    path_segs = [s for s in path.split("/") if s]
    # Body/query fields first (the usual fuzz targets); path segments last so a route name
    # like "search" or "enrollments" isn't accidentally the default selection.
    fuzzable = body_fields + [("query", k) for k, _ in query] + [("path", s) for s in path_segs]
    return {"source": "postman", "method": method, "scheme": scheme, "path": path,
            "headers": headers, "body": body, "query": query, "fuzzable": fuzzable,
            "json_obj": json_obj, "json_paths": json_paths}


def _json_leaves(obj, prefix=""):
    """Map a JSON object to settable fuzz targets: label -> (pathlist, is_array).
    Scalars (incl. null) become one target; arrays become one target (replaced with [payload])."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, list):
                out[p + "[]"] = (_path_to(prefix, k), True)
            elif isinstance(v, dict):
                out.update(_json_leaves(v, p))
            else:
                out[p] = (_path_to(prefix, k), False)
    return out


def _path_to(prefix, key):
    base = [p for p in prefix.split(".") if p] if prefix else []
    return base + [key]


def set_fuzz_point(target, kind, key):
    """Insert the FUZZ marker into the chosen field.
    Returns (method, path, headers, body, scheme, ctx) where ctx tells apply_payload how to
    encode the payload: 'url' (path/query), 'json' (JSON body), 'form' (urlencoded body)."""
    path, query, body = target["path"], list(target.get("query", [])), target["body"]
    ctx = "url"
    if kind == "path":
        segs = path.split("/")
        for i, s in enumerate(segs):
            if s == key:
                segs[i] = MARKER
                break
        path = "/".join(segs)
        ctx = "url"
    elif kind == "query":
        query = [(k, (MARKER if k == key else v)) for k, v in query]
        ctx = "url"
    elif kind == "form":
        pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
        body = urllib.parse.urlencode([(k, (MARKER if k == key else v)) for k, v in pairs], safe=MARKER)
        ctx = "form"
    elif kind == "json":
        import copy
        obj = copy.deepcopy(target["json_obj"])
        pathlist, is_array = target["json_paths"][key]
        _json_set(obj, pathlist, [MARKER] if is_array else MARKER)
        body = json.dumps(obj)
        ctx = "json"
    if query:
        path = path + "?" + urllib.parse.urlencode(query, safe=MARKER)
    return target["method"], path, dict(target["headers"]), body, target["scheme"], ctx


def _json_set(obj, pathlist, value):
    cur = obj
    for k in pathlist[:-1]:
        cur = cur[k]
    cur[pathlist[-1]] = value


# ----------------------------- payloads -----------------------------

def load_payloads(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f
                if line.strip() != "" and line.strip() != "#" and not line.lstrip().startswith("# ")]


# ----------------------------- sending -----------------------------

def build_url(scheme, headers, path):
    host = headers.get("Host") or headers.get("host")
    if not host:
        raise ValueError("No Host header found.")
    return f"{scheme}://{host}{path}"


def apply_payload(path, headers, body, payload, ctx="url"):
    """Insert the payload where the marker is, encoding it correctly for its context:
    url -> percent-encoded in the path/query; json -> JSON-string-escaped in the body;
    form -> form-encoded in the body; raw -> inserted verbatim (Burp raw requests)."""
    url_enc = urllib.parse.quote(payload, safe="")
    if "?" in path:
        p, q = path.split("?", 1)
        new_path = p.replace(MARKER, url_enc) + "?" + q.replace(MARKER, url_enc)
    else:
        new_path = path.replace(MARKER, url_enc)
    new_headers = {k: v.replace(MARKER, payload) for k, v in headers.items()}
    if ctx == "json":
        import re
        if re.fullmatch(r"-?\d+(?:\.\d+)?", payload) and ('"' + MARKER + '"') in body:
            # numeric payload into a JSON value -> insert as a real number (e.g. ids), not a string
            new_body = body.replace('"' + MARKER + '"', payload)
        else:
            new_body = body.replace(MARKER, json.dumps(payload)[1:-1])  # escaped string content
    elif ctx == "form":
        new_body = body.replace(MARKER, urllib.parse.quote_plus(payload))
    elif ctx == "raw":
        new_body = body.replace(MARKER, payload)
    else:  # url
        new_body = body.replace(MARKER, url_enc)
    return new_path, new_headers, new_body


def reflection_kind(body_text, payload, canary, content_type=""):
    """Classify how the payload came back. 'RAW-XSS?' only when the response is HTML AND an
    HTML-dangerous chunk of the payload is present unescaped — a JSON/text echo is not XSS."""
    ct = (content_type or "").lower()
    is_html = "html" in ct
    html_markers = ("<script", "<img", "<svg", "onerror=", "onmouseover=", "javascript:")
    danger_unescaped = any(m in payload.lower() and m in body_text.lower() for m in html_markers)
    if canary and canary in body_text:
        if danger_unescaped and is_html:
            return "RAW-XSS? (html)"
        if danger_unescaped:
            return "reflected (not html)"
        return "reflected"
    if canary and (html.escape(canary) in body_text or urllib.parse.quote(canary) in body_text):
        return "encoded"
    if payload and payload in body_text:
        return "payload-reflected"
    return ""


def send(url, method, headers, body, timeout, insecure):
    data = body.encode("utf-8") if body else None
    skip = {"content-length", "accept-encoding"}
    send_headers = {k: v for k, v in headers.items() if k.lower() not in skip}
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
            ct = resp.headers.get("Content-Type", "")
            return resp.status, len(raw), time.time() - start, raw.decode("utf-8", "replace"), "", ct
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        ct = e.headers.get("Content-Type", "") if hasattr(e, "headers") and e.headers else ""
        return e.code, len(raw), time.time() - start, raw.decode("utf-8", "replace"), "", ct
    except Exception as e:
        return "ERR", 0, time.time() - start, "", f"{type(e).__name__}: {e}", ""


def run(method, path, headers, body, scheme, payloads, *, ctx="url", canary="FZcanary",
        delay=0.3, timeout=20, insecure=False, baseline=False, save_bodies=False,
        progress=None):
    """Generator: yields a result dict per payload. `progress(i, total)` is optional."""
    stamp = f"{dt.datetime.now():%Y%m%d-%H%M%S}"
    out_path = os.path.join(results_dir(), f"results-{stamp}.csv")
    bodies_dir = ""
    if save_bodies:
        bodies_dir = os.path.join(bodies_root(), f"bodies-{stamp}")
        os.makedirs(bodies_dir, exist_ok=True)

    base_len = base_status = None
    if baseline:
        bp, bh, bb = apply_payload(path, headers, body, canary, ctx)
        base_status, base_len, _, _, _, _ = send(build_url(scheme, bh, bp), method, bh, bb, timeout, insecure)

    rows = []
    total = len(payloads)
    for i, payload in enumerate(payloads, 1):
        pp, ph, pb = apply_payload(path, headers, body, payload, ctx)
        url = build_url(scheme, ph, pp)
        status, length, elapsed, text, err, content_type = send(url, method, ph, pb, timeout, insecure)
        refl = reflection_kind(text, payload, canary, content_type)
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
        flagged = bool(diff) or "XSS?" in refl or (isinstance(status, int) and status >= 500)
        row = {"n": i, "status": status, "length": length, "time_s": f"{elapsed:.3f}",
               "reflection": refl, "diff": diff, "url": url, "payload": payload,
               "content_type": content_type, "body_snippet": snippet, "error": err, "flagged": flagged}
        rows.append(row)
        if progress:
            progress(i, total)
        yield row
        time.sleep(delay)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["n", "status", "length", "time_s", "reflection",
                                          "diff", "url", "payload", "content_type",
                                          "body_snippet", "error"])
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in w.fieldnames})
    # Final sentinel so callers know where output went.
    yield {"done": True, "csv": out_path, "bodies_dir": bodies_dir, "count": len(rows)}
