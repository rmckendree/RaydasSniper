#!/usr/bin/env python3
"""
LMS Fuzzer — desktop GUI (authorized security testing only).

A simple Sniper-style API fuzzer with a window: pick a Burp raw request or a Postman
collection, choose the request and the field to fuzz, pick a payload list, hit Run.
Results stream into a table; CSV + response bodies are saved under the project folders.

Pure standard library (tkinter). Engine lives in fuzzcore.py.
"""
import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import fuzzcore as fc

ROOT = fc.data_root()                       # writable: payloads/Requests/results/bodies
ASSETS = os.path.join(fc.resource_dir(), "assets")   # read-only bundle: logo files
REQ_DIR = os.path.join(ROOT, "Requests")
PAY_DIR = os.path.join(ROOT, "payloads")

ACCENT = "#2d6cdf"
BG = "#f4f1ec"
FLAG_BG = "#ffe3e3"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LMS Fuzzer")
        self.configure(bg=BG)
        self.geometry("980x680")
        self.minsize(820, 560)

        self._set_icon()
        self.collection = None
        self.variables = {}
        self.reqs = []            # [(name, request_dict)]
        self.target = None        # resolved request_target dict
        self.q = queue.Queue()
        self.running = False
        self.last_csv = None
        self.last_bodies = None

        self._build_header()
        self._build_form()
        self._build_table()
        self._build_footer()

    # ---------- window chrome ----------
    def _set_icon(self):
        try:
            if os.name == "nt":
                # Give the process its own AppUserModelID so Windows shows OUR icon in the
                # taskbar instead of grouping under the generic Python icon.
                try:
                    import ctypes
                    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("LMSFuzzer.App")
                except Exception:
                    pass
                self.iconbitmap(os.path.join(ASSETS, "logo.ico"))
                # Also set a PhotoImage icon as a fallback for the window/taskbar.
                try:
                    self._tbicon = tk.PhotoImage(file=os.path.join(ASSETS, "logo_64.png"))
                    self.iconphoto(True, self._tbicon)
                except Exception:
                    pass
            else:
                self._tbicon = tk.PhotoImage(file=os.path.join(ASSETS, "logo_128.png"))
                self.iconphoto(True, self._tbicon)
        except Exception:
            pass

    def _build_header(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=16, pady=(14, 6))
        try:
            self.logo = tk.PhotoImage(file=os.path.join(ASSETS, "logo_64.png"))
            tk.Label(bar, image=self.logo, bg=BG).pack(side="left")
        except Exception:
            pass
        box = tk.Frame(bar, bg=BG)
        box.pack(side="left", padx=12)
        tk.Label(box, text="LMS Fuzzer", bg=BG, fg="#222",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(box, text="Sniper-style API fuzzer · authorized testing only",
                 bg=BG, fg="#777", font=("Segoe UI", 10)).pack(anchor="w")

    # ---------- form ----------
    def _row(self, parent, r):
        parent.grid_columnconfigure(1, weight=1)

    def _build_form(self):
        f = tk.Frame(self, bg=BG)
        f.pack(fill="x", padx=16)
        for c in (1,):
            f.grid_columnconfigure(c, weight=1)

        def label(txt, r):
            tk.Label(f, text=txt, bg=BG, anchor="w", font=("Segoe UI", 10)).grid(
                row=r, column=0, sticky="w", pady=4, padx=(0, 8))

        # Request file
        label("Request / collection", 0)
        self.req_var = tk.StringVar()
        tk.Entry(f, textvariable=self.req_var).grid(row=0, column=1, sticky="ew")
        tk.Button(f, text="Browse…", command=self.pick_request).grid(row=0, column=2, padx=6)

        # Postman request + field (shown when a collection is chosen)
        label("Request", 1)
        self.request_cb = ttk.Combobox(f, state="disabled", values=[])
        self.request_cb.grid(row=1, column=1, sticky="ew")
        self.request_cb.bind("<<ComboboxSelected>>", self.on_request_selected)

        label("Field to fuzz", 2)
        self.field_cb = ttk.Combobox(f, state="disabled", values=[])
        self.field_cb.grid(row=2, column=1, sticky="ew")

        # Token + env (postman)
        label("Bearer token (optional)", 3)
        self.token_var = tk.StringVar()
        tk.Entry(f, textvariable=self.token_var, show="•").grid(row=3, column=1, sticky="ew")

        label("Payload list", 4)
        self.pay_var = tk.StringVar()
        tk.Entry(f, textvariable=self.pay_var).grid(row=4, column=1, sticky="ew")
        tk.Button(f, text="Browse…", command=self.pick_payloads).grid(row=4, column=2, padx=6)

        # Options row
        opt = tk.Frame(self, bg=BG)
        opt.pack(fill="x", padx=16, pady=(10, 4))
        tk.Label(opt, text="Scheme", bg=BG).pack(side="left")
        self.scheme_var = tk.StringVar(value="https")
        ttk.Combobox(opt, textvariable=self.scheme_var, values=["https", "http"],
                     width=7, state="readonly").pack(side="left", padx=(4, 14))
        tk.Label(opt, text="Delay (s)", bg=BG).pack(side="left")
        self.delay_var = tk.StringVar(value="0.3")
        tk.Spinbox(opt, textvariable=self.delay_var, from_=0, to=10, increment=0.1,
                   width=5).pack(side="left", padx=(4, 14))
        self.baseline_var = tk.BooleanVar(value=True)
        self.bodies_var = tk.BooleanVar(value=True)
        self.insecure_var = tk.BooleanVar(value=False)
        tk.Checkbutton(opt, text="Baseline + flag diffs", variable=self.baseline_var,
                       bg=BG).pack(side="left")
        tk.Checkbutton(opt, text="Save bodies", variable=self.bodies_var, bg=BG).pack(side="left")
        tk.Checkbutton(opt, text="Skip TLS check", variable=self.insecure_var,
                       bg=BG).pack(side="left")

        # Run row
        runrow = tk.Frame(self, bg=BG)
        runrow.pack(fill="x", padx=16, pady=(4, 8))
        self.run_btn = tk.Button(runrow, text="▶  Run fuzz", command=self.start_run,
                                 bg=ACCENT, fg="white", font=("Segoe UI", 11, "bold"),
                                 relief="flat", padx=16, pady=6)
        self.run_btn.pack(side="left")
        self.target_lbl = tk.Label(runrow, text="", bg=BG, fg="#555", font=("Segoe UI", 9))
        self.target_lbl.pack(side="left", padx=12)

    # ---------- table ----------
    def _build_table(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=16, pady=4)
        cols = ("n", "status", "length", "time", "reflection", "payload")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=12)
        widths = {"n": 40, "status": 70, "length": 80, "time": 70, "reflection": 140, "payload": 460}
        for c in cols:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.tag_configure("flag", background=FLAG_BG)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

    # ---------- footer ----------
    def _build_footer(self):
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=16, pady=(4, 12))
        self.progress = ttk.Progressbar(foot, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True)
        self.status_lbl = tk.Label(foot, text="Ready.", bg=BG, fg="#555",
                                   font=("Segoe UI", 9), width=28, anchor="w")
        self.status_lbl.pack(side="left", padx=10)
        self.open_csv_btn = tk.Button(foot, text="Open results CSV", state="disabled",
                                      command=self.open_csv)
        self.open_csv_btn.pack(side="left", padx=4)
        self.open_bodies_btn = tk.Button(foot, text="Open bodies folder", state="disabled",
                                         command=self.open_bodies)
        self.open_bodies_btn.pack(side="left", padx=4)

    # ---------- actions ----------
    def pick_request(self):
        p = filedialog.askopenfilename(
            title="Select a Burp raw request (FUZZ) or a Postman collection (*.json)",
            initialdir=REQ_DIR if os.path.isdir(REQ_DIR) else ROOT,
            filetypes=[("Requests", "*.txt *.req *.json"), ("All files", "*.*")])
        if not p:
            return
        self.req_var.set(p)
        self._load_request(p)

    def _load_request(self, p):
        self.request_cb.set("")
        self.field_cb.set("")
        self.request_cb.configure(state="disabled", values=[])
        self.field_cb.configure(state="disabled", values=[])
        self.target = None
        if p.lower().endswith(".json"):
            try:
                overrides = {"token": self.token_var.get()} if self.token_var.get() else {}
                self.collection, self.variables, self.reqs = fc.load_collection(p, None, overrides)
            except Exception as e:
                messagebox.showerror("Could not read collection", str(e))
                return
            names = [f"{i+1}. {r.get('method','GET')}  {n}" for i, (n, r) in enumerate(self.reqs)]
            self.request_cb.configure(state="readonly", values=names)
            if len(self.reqs) == 1:
                self.request_cb.current(0)
                self.on_request_selected()
            self.status_lbl.config(text=f"{len(self.reqs)} request(s) loaded.")
        else:
            try:
                with open(p, "r", encoding="utf-8") as f:
                    raw = fc.parse_raw_request(f.read())
            except Exception as e:
                messagebox.showerror("Could not read request", str(e))
                return
            if not raw["has_marker"]:
                messagebox.showwarning("No FUZZ marker",
                                       "This raw request has no FUZZ marker. Add the word FUZZ "
                                       "where the payload should go, then re-select the file.")
                return
            self.target = {"source": "raw", **raw}
            self.target_lbl.config(text=f"{raw['method']} {raw['path']}")

    def on_request_selected(self, *_):
        idx = self.request_cb.current()
        if idx < 0:
            return
        overrides = {"token": self.token_var.get()} if self.token_var.get() else {}
        self.variables = fc.collect_variables(self.collection, None, overrides)
        _, request = self.reqs[idx]
        self.target = fc.request_target(request, self.variables, self.collection)
        opts = [f"{kind}: {key}" for kind, key in self.target["fuzzable"]]
        self.field_cb.configure(state="readonly", values=opts)
        if opts:
            self.field_cb.current(0)
        else:
            messagebox.showwarning("Nothing to fuzz",
                                   "This request has no path/query/body fields to fuzz.")
        self.target_lbl.config(text=f"{self.target['method']} {self.target['path']}")

    def pick_payloads(self):
        p = filedialog.askopenfilename(
            title="Select the payload list (one per line)",
            initialdir=PAY_DIR if os.path.isdir(PAY_DIR) else ROOT,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if p:
            self.pay_var.set(p)

    def start_run(self):
        if self.running:
            return
        if not self.target:
            messagebox.showwarning("Pick a request", "Choose a request/collection first.")
            return
        if not self.pay_var.get() or not os.path.isfile(self.pay_var.get()):
            messagebox.showwarning("Pick payloads", "Choose a payload list first.")
            return
        # Build the fuzz target.
        try:
            if self.target["source"] == "postman":
                sel = self.field_cb.get()
                if not sel or ": " not in sel:
                    messagebox.showwarning("Pick a field", "Choose the field to fuzz.")
                    return
                kind, key = sel.split(": ", 1)
                method, path, headers, body, scheme, ctx = fc.set_fuzz_point(self.target, kind, key)
                scheme = scheme or self.scheme_var.get()
            else:
                t = self.target
                method, path, headers, body = t["method"], t["path"], t["headers"], t["body"]
                scheme = t["scheme"] or self.scheme_var.get()
                ctx = "raw"
            payloads = fc.load_payloads(self.pay_var.get())
            if not payloads:
                messagebox.showwarning("Empty payloads", "That payload file has no usable lines.")
                return
            delay = float(self.delay_var.get() or "0.3")
        except Exception as e:
            messagebox.showerror("Could not prepare run", str(e))
            return

        # reset UI
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.progress.configure(maximum=len(payloads), value=0)
        self.running = True
        self.run_btn.configure(state="disabled", text="Running…")
        self.open_csv_btn.configure(state="disabled")
        self.open_bodies_btn.configure(state="disabled")
        self.status_lbl.config(text=f"Sending {len(payloads)} requests…")

        args = dict(ctx=ctx, canary="FZcanary", delay=delay, timeout=20,
                    insecure=self.insecure_var.get(), baseline=self.baseline_var.get(),
                    save_bodies=self.bodies_var.get())
        t = threading.Thread(target=self._worker,
                             args=(method, path, headers, body, scheme, payloads, args),
                             daemon=True)
        t.start()
        self.after(80, self._drain)

    def _worker(self, method, path, headers, body, scheme, payloads, args):
        try:
            for row in fc.run(method, path, headers, body, scheme, payloads, **args):
                self.q.put(row)
        except Exception as e:
            self.q.put({"error_fatal": str(e)})

    def _drain(self):
        try:
            while True:
                row = self.q.get_nowait()
                if "error_fatal" in row:
                    messagebox.showerror("Run failed", row["error_fatal"])
                    self._finish()
                    return
                if row.get("done"):
                    self.last_csv = row["csv"]
                    self.last_bodies = row.get("bodies_dir") or None
                    self._finish(row["count"])
                    return
                vals = (row["n"], row["status"], row["length"], row["time_s"],
                        row["reflection"] or "-", row["payload"])
                tag = ("flag",) if row.get("flagged") else ()
                self.tree.insert("", "end", values=vals, tags=tag)
                self.tree.yview_moveto(1.0)
                self.progress.step(1)
        except queue.Empty:
            pass
        if self.running:
            self.after(80, self._drain)

    def _finish(self, count=None):
        self.running = False
        self.run_btn.configure(state="normal", text="▶  Run fuzz")
        if count is not None:
            flagged = len(self.tree.tag_has("flag"))
            self.status_lbl.config(text=f"Done · {count} sent · {flagged} flagged")
            self.open_csv_btn.configure(state="normal")
            if self.last_bodies:
                self.open_bodies_btn.configure(state="normal")

    def _reveal(self, path):
        if not path or not os.path.exists(path):
            return
        try:
            if os.name == "nt":
                os.startfile(path)  # noqa
            elif sys_is_mac():
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            messagebox.showinfo("Path", path)

    def open_csv(self):
        self._reveal(self.last_csv)

    def open_bodies(self):
        self._reveal(self.last_bodies)


def sys_is_mac():
    import sys
    return sys.platform == "darwin"


if __name__ == "__main__":
    App().mainloop()
