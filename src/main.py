"""
FirmwareGuard - Firmware Security Analyzer
Main GUI entry point  (v1.1)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import sys
from pathlib import Path

# When bundled by PyInstaller, sys._MEIPASS points to the temp extraction dir.
# Add both the script dir and MEIPASS so our modules are always importable.
_base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
if _base not in sys.path:
    sys.path.insert(0, _base)

from analyzer import FirmwareAnalyzer
from report import ReportGenerator


SUPPORTED_EXTENSIONS = (
    ".iso", ".bin", ".zip", ".tar", ".tar.gz", ".tgz",
    ".gz", ".img", ".rom", ".fw", ".elf", ".hex", ".srec",
    ".mot", ".dfu", ".upd", ".pak", ".squashfs", ".cramfs",
    ".ext2", ".ext3", ".ext4", ".7z", ".rar"
)

ACCENT      = "#1e88e5"
ACCENT_DARK = "#1565c0"
BG          = "#0f1117"
SURFACE     = "#1a1d27"
SURFACE2    = "#22263a"
SURFACE3    = "#2a2f47"
TEXT        = "#e8eaf6"
TEXT_DIM    = "#7986cb"
SUCCESS     = "#43a047"
WARNING     = "#fb8c00"
DANGER      = "#e53935"
CRITICAL_C  = "#b71c1c"

SEV_COLORS = {
    "CRITICAL": CRITICAL_C,
    "HIGH":     DANGER,
    "MEDIUM":   WARNING,
    "LOW":      "#ffee58",
    "INFO":     TEXT_DIM,
    "OK":       SUCCESS,
}


# ---------------------------------------------------------------------------
class DetailPanel(tk.Toplevel):
    """Modal window showing full finding details when a row is clicked."""

    def __init__(self, parent, finding: dict):
        super().__init__(parent)
        sev   = finding.get("severity", "INFO")
        title = finding.get("title", "Finding Detail")
        color = SEV_COLORS.get(sev, TEXT_DIM)

        self.title(f"Finding — {title}")
        self.configure(bg=BG)
        self.geometry("780x640")
        self.minsize(600, 480)
        self.resizable(True, True)
        self.grab_set()
        self.focus_set()

        self._build(finding, color, sev)
        self._center(parent)

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width()  - self.winfo_width())  // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def _build(self, f, color, sev):
        # Coloured top bar
        tk.Frame(self, bg=color, height=5).pack(fill="x")

        # Header
        hdr = tk.Frame(self, bg=SURFACE, pady=14, padx=20)
        hdr.pack(fill="x")

        pill = tk.Label(hdr, text=f"  {sev}  ", bg=color, fg="white",
                        font=("Segoe UI", 9, "bold"), padx=6, pady=2)
        pill.pack(side="left")

        tk.Label(hdr, text=f"  {f.get('category','')}", bg=SURFACE,
                 fg=TEXT_DIM, font=("Segoe UI", 9)).pack(side="left")

        tk.Label(hdr, text=f.get("title", ""), bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 13, "bold"),
                 wraplength=720, justify="left").pack(anchor="w", pady=(10, 0))

        cvss = f.get("cvss", "")
        if cvss:
            tk.Label(hdr, text=f"CVSS  {cvss}", bg=SURFACE, fg=color,
                     font=("Consolas", 9)).pack(anchor="w", pady=(4, 0))

        # Scrollable body
        outer  = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        vsb    = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        body   = tk.Frame(canvas, bg=BG)
        win_id = canvas.create_window((0, 0), window=body, anchor="nw")

        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(win_id, width=e.width))
        body.bind("<Configure>",
                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        pad = dict(padx=22, pady=0)

        detail = f.get("detail", "")
        if detail:
            self._section(body, "📍 Location / Evidence", color)
            self._code(body, detail, **pad)

        for icon, key, label in [
            ("📖", "description", "Description"),
            ("💥", "impact",      "Impact"),
            ("🔧", "remediation", "Remediation"),
        ]:
            val = f.get(key, "")
            if val:
                self._section(body, f"{icon} {label}", color)
                self._para(body, val, **pad)

        refs = f.get("references", [])
        if refs:
            self._section(body, "🔗 References", color)
            for ref in refs:
                row = tk.Frame(body, bg=BG)
                row.pack(fill="x", **pad, pady=1)
                tk.Label(row, text="•", bg=BG, fg=color,
                         font=("Segoe UI", 10)).pack(side="left", padx=(0, 6))
                tk.Label(row, text=ref, bg=BG, fg=TEXT_DIM,
                         font=("Segoe UI", 9), wraplength=680,
                         justify="left").pack(side="left", anchor="w")

        tk.Frame(body, bg=BG, height=20).pack()

        # Close button
        ft = tk.Frame(self, bg=SURFACE, pady=10)
        ft.pack(fill="x", side="bottom")
        tk.Button(ft, text="Close", command=self.destroy,
                  bg=SURFACE3, fg=TEXT,
                  activebackground=ACCENT, activeforeground="white",
                  relief="flat", font=("Segoe UI", 10),
                  padx=24, pady=6, cursor="hand2").pack(side="right", padx=20)

    def _section(self, parent, text, color):
        tk.Frame(parent, bg=BG, height=10).pack()
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", padx=22)
        tk.Frame(row, bg=color, width=3).pack(side="left", fill="y")
        tk.Label(row, text=f"  {text}", bg=BG, fg=TEXT,
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Frame(parent, bg=BG, height=5).pack()

    def _para(self, parent, text, **kw):
        tk.Label(parent, text=text, bg=BG, fg=TEXT,
                 font=("Segoe UI", 10), wraplength=700,
                 justify="left", anchor="w").pack(fill="x", **kw)

    def _code(self, parent, text, **kw):
        fr = tk.Frame(parent, bg=SURFACE2, padx=12, pady=8)
        fr.pack(fill="x", **kw)
        tk.Label(fr, text=text, bg=SURFACE2, fg="#a5d6a7",
                 font=("Consolas", 9), wraplength=700,
                 justify="left", anchor="w").pack(fill="x")


# ---------------------------------------------------------------------------
class FirmwareGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FirmwareGuard — Firmware Security Analyzer")
        self.geometry("960x700")
        self.minsize(800, 560)
        self.configure(bg=BG)
        self._style()
        self._build_ui()

        self.analyzer     = None
        self.report_gen   = ReportGenerator()
        self.current_file = None
        self.last_report  = None
        self._findings    = []

    # ── Styles ──────────────────────────────────────────────────────────────
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".",              background=BG, foreground=TEXT,
                    font=("Segoe UI", 10))
        s.configure("TFrame",         background=BG)
        s.configure("TLabel",         background=BG, foreground=TEXT)
        s.configure("Dim.TLabel",     background=BG, foreground=TEXT_DIM,
                    font=("Segoe UI", 9))
        s.configure("Title.TLabel",   background=BG, foreground=TEXT,
                    font=("Segoe UI", 18, "bold"))
        s.configure("Sub.TLabel",     background=BG, foreground=TEXT_DIM,
                    font=("Segoe UI", 10))

        s.configure("Accent.TButton", background=ACCENT, foreground="white",
                    font=("Segoe UI", 10, "bold"), borderwidth=0,
                    focusthickness=0, padding=(16, 8))
        s.map("Accent.TButton",
              background=[("active", ACCENT_DARK), ("disabled", "#37474f")],
              foreground=[("disabled", "#90a4ae")])

        s.configure("Ghost.TButton", background=SURFACE2, foreground=TEXT,
                    font=("Segoe UI", 10), borderwidth=0,
                    focusthickness=0, padding=(12, 7))
        s.map("Ghost.TButton",
              background=[("active", "#2e3250"), ("disabled", "#1c2030")],
              foreground=[("disabled", "#546e7a")])

        s.configure("Accent.Horizontal.TProgressbar",
                    troughcolor=SURFACE2, background=ACCENT,
                    borderwidth=0, thickness=6)

        s.configure("Log.Treeview",
                    background=SURFACE, foreground=TEXT,
                    fieldbackground=SURFACE, rowheight=26,
                    borderwidth=0, font=("Segoe UI", 9))
        s.configure("Log.Treeview.Heading",
                    background=SURFACE2, foreground=TEXT_DIM,
                    font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Log.Treeview",
              background=[("selected", ACCENT_DARK)],
              foreground=[("selected", "white")])

    # ── UI layout ────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = ttk.Frame(self, padding=(24, 18, 24, 0))
        hdr.pack(fill="x")
        ttk.Label(hdr, text="🛡 FirmwareGuard",
                  style="Title.TLabel").pack(side="left")
        ttk.Label(hdr, text="v1.1 — Firmware Security Analyzer",
                  style="Sub.TLabel").pack(side="left", padx=(10, 0), pady=(6, 0))

        # Drop zone
        pf = ttk.Frame(self, padding=(24, 14, 24, 0))
        pf.pack(fill="x")
        self.drop_frame = tk.Frame(pf, bg=SURFACE2,
                                   highlightbackground=ACCENT,
                                   highlightthickness=2, cursor="hand2")
        self.drop_frame.pack(fill="x", ipady=18)
        self.drop_frame.bind("<Button-1>", lambda e: self._pick_file())
        inner = tk.Frame(self.drop_frame, bg=SURFACE2)
        inner.pack()
        tk.Label(inner, text="📂  Click to browse firmware file",
                 bg=SURFACE2, fg=TEXT, font=("Segoe UI", 11)).pack()
        tk.Label(inner,
                 text="ISO  BIN  ZIP  TAR  GZ  IMG  ROM  ELF  HEX  FW  …",
                 bg=SURFACE2, fg=TEXT_DIM, font=("Segoe UI", 9)).pack()

        # File row
        fr = ttk.Frame(self, padding=(24, 6, 24, 0))
        fr.pack(fill="x")
        self.lbl_file = ttk.Label(fr, text="No file selected",
                                  style="Dim.TLabel")
        self.lbl_file.pack(side="left")
        self.btn_clear = ttk.Button(fr, text="✕ Clear",
                                    style="Ghost.TButton",
                                    command=self._clear_file)
        self.btn_clear.pack(side="right")
        self.btn_clear.state(["disabled"])

        # Controls
        ctrl = ttk.Frame(self, padding=(24, 8, 24, 0))
        ctrl.pack(fill="x")
        self.btn_scan = ttk.Button(ctrl, text="▶  Run Security Scan",
                                   style="Accent.TButton",
                                   command=self._start_scan)
        self.btn_scan.pack(side="left")
        self.btn_scan.state(["disabled"])

        self.btn_report = ttk.Button(ctrl, text="📄  Open Report",
                                     style="Ghost.TButton",
                                     command=self._open_report)
        self.btn_report.pack(side="left", padx=(10, 0))
        self.btn_report.state(["disabled"])

        self.btn_save = ttk.Button(ctrl, text="💾  Save Report",
                                   style="Ghost.TButton",
                                   command=self._save_report)
        self.btn_save.pack(side="left", padx=(8, 0))
        self.btn_save.state(["disabled"])

        # Progress
        pf2 = ttk.Frame(self, padding=(24, 8, 24, 0))
        pf2.pack(fill="x")
        self.progress = ttk.Progressbar(pf2,
                                        style="Accent.Horizontal.TProgressbar",
                                        mode="determinate", maximum=100)
        self.progress.pack(fill="x")
        self.lbl_status = ttk.Label(pf2, text="Idle", style="Dim.TLabel")
        self.lbl_status.pack(anchor="w", pady=(3, 0))
        ttk.Label(pf2,
                  text="💡  Click any finding row to see full description, "
                       "impact and remediation",
                  style="Dim.TLabel").pack(anchor="w", pady=(1, 0))

        # Findings treeview
        lf = ttk.Frame(self, padding=(24, 6, 24, 16))
        lf.pack(fill="both", expand=True)

        cols = ("severity", "category", "finding", "location")
        self.tree = ttk.Treeview(lf, columns=cols, show="headings",
                                 style="Log.Treeview", cursor="hand2")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("category", text="Category")
        self.tree.heading("finding",  text="Finding")
        self.tree.heading("location", text="Location / Evidence")

        self.tree.column("severity", width=95,  anchor="center", stretch=False)
        self.tree.column("category", width=150, anchor="w",      stretch=False)
        self.tree.column("finding",  width=310, anchor="w")
        self.tree.column("location", width=310, anchor="w")

        vsb = ttk.Scrollbar(lf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.tag_configure("CRITICAL", foreground=CRITICAL_C,
                                background="#3b0d0d")
        self.tree.tag_configure("HIGH",     foreground=DANGER,
                                background="#2d0d0d")
        self.tree.tag_configure("MEDIUM",   foreground=WARNING,
                                background="#2d1d00")
        self.tree.tag_configure("LOW",      foreground="#ffee58",
                                background="#1f1d00")
        self.tree.tag_configure("INFO",     foreground=TEXT_DIM,
                                background=SURFACE)
        self.tree.tag_configure("OK",       foreground=SUCCESS,
                                background="#0d1f0d")

        self.tree.bind("<ButtonRelease-1>", self._on_row_click)
        self.tree.bind("<Return>",          self._on_row_click)
        self.tree.bind("<Double-1>",        self._on_row_click)

    # ── File handling ────────────────────────────────────────────────────────
    def _pick_file(self):
        path = filedialog.askopenfilename(
            title="Select Firmware File",
            filetypes=[
                ("Firmware files",
                 " ".join(f"*{e}" for e in SUPPORTED_EXTENSIONS)),
                ("All files", "*.*"),
            ])
        if path:
            self._set_file(path)

    def _set_file(self, path):
        self.current_file = path
        size_str = self._fmt_size(os.path.getsize(path))
        self.lbl_file.configure(
            text=f"📁  {os.path.basename(path)}   ({size_str})",
            foreground=TEXT)
        self.btn_scan.state(["!disabled"])
        self.btn_clear.state(["!disabled"])
        self._clear_tree()
        self._set_status("File loaded — ready to scan.", TEXT_DIM)
        self.progress["value"] = 0

    def _clear_file(self):
        self.current_file = None
        self.lbl_file.configure(text="No file selected", foreground=TEXT_DIM)
        for b in (self.btn_scan, self.btn_clear,
                  self.btn_report, self.btn_save):
            b.state(["disabled"])
        self._clear_tree()
        self._set_status("Idle", TEXT_DIM)
        self.progress["value"] = 0
        self.last_report = None

    def _clear_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._findings = []

    # ── Row click ────────────────────────────────────────────────────────────
    def _on_row_click(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        tags = self.tree.item(sel[0], "tags")
        try:
            idx_tag = next(t for t in tags if t.startswith("idx_"))
            finding = self._findings[int(idx_tag[4:])]
            DetailPanel(self, finding)
        except (StopIteration, IndexError, ValueError):
            pass

    # ── Scan ─────────────────────────────────────────────────────────────────
    def _start_scan(self):
        if not self.current_file:
            return
        self.btn_scan.state(["disabled"])
        self.btn_report.state(["disabled"])
        self.btn_save.state(["disabled"])
        self._clear_tree()
        self.progress["value"] = 0
        self._set_status("Starting analysis…", ACCENT)
        self.analyzer = FirmwareAnalyzer(self.current_file)
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        try:
            for update in self.analyzer.analyze():
                t = update.get("type")
                if t == "progress":
                    self.after(0, lambda v=update["value"],
                               m=update["message"]: self._on_progress(v, m))
                elif t == "finding":
                    self.after(0, lambda f=update: self._on_finding(f))
            self.after(0, self._on_scan_done)
        except Exception as exc:
            self.after(0, lambda e=str(exc): self._on_scan_error(e))

    def _on_progress(self, value, message):
        self.progress["value"] = value
        self._set_status(message, ACCENT)

    def _on_finding(self, f):
        sev = f.get("severity", "INFO")
        idx = len(self._findings)
        self._findings.append(f)
        self.tree.insert("", "end",
                         values=(sev, f.get("category", ""),
                                 f.get("title", ""), f.get("detail", "")),
                         tags=(sev, f"idx_{idx}"))

    def _on_scan_done(self):
        self.progress["value"] = 100
        findings = self.analyzer.findings
        nc = sum(1 for f in findings if f["severity"] == "CRITICAL")
        nh = sum(1 for f in findings if f["severity"] == "HIGH")
        nm = sum(1 for f in findings if f["severity"] == "MEDIUM")
        nl = sum(1 for f in findings if f["severity"] == "LOW")
        msg = (f"Scan complete — {nc} Critical  {nh} High  "
               f"{nm} Medium  {nl} Low  ·  click any row for details")
        self._set_status(msg, SUCCESS if nc == 0 else DANGER)
        self.last_report = self.report_gen.generate(
            filepath=self.current_file,
            findings=findings,
            meta=self.analyzer.meta)
        self.btn_scan.state(["!disabled"])
        self.btn_report.state(["!disabled"])
        self.btn_save.state(["!disabled"])

    def _on_scan_error(self, msg):
        self._set_status(f"Error: {msg}", DANGER)
        self.btn_scan.state(["!disabled"])
        messagebox.showerror("Scan Error", msg)

    # ── Report ───────────────────────────────────────────────────────────────
    def _open_report(self):
        if not self.last_report:
            return
        import tempfile, webbrowser
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                         delete=False,
                                         encoding="utf-8") as fh:
            fh.write(self.last_report)
            tmp = fh.name
        webbrowser.open(f"file:///{tmp.replace(os.sep, '/')}")

    def _save_report(self):
        if not self.last_report:
            return
        stem = Path(self.current_file).stem
        path = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=".html",
            initialfile=f"{stem}_security_report.html",
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.last_report)
            messagebox.showinfo("Saved", f"Report saved to:\n{path}")

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _set_status(self, text, color=TEXT_DIM):
        self.lbl_status.configure(text=text, foreground=color)

    @staticmethod
    def _fmt_size(n):
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = FirmwareGuardApp()
    app.mainloop()
