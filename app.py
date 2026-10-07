"""
RAM Optimizer — GUI.

Tabs:
  * Processes — scan, see tier classification, free SAFE/REVIEW items (with
    confirmation). Freeing a process adds it to the watchdog blocklist.
  * Blocked   — the session blocklist. Toggle any item back on (release) or
    re-enable blocking. Shows re-kill counts from the watchdog.
  * Optimize Windows — list removable preinstalled apps, remove with per-item
    confirmation.
  * Activity  — the audit log of everything the app did.

Every destructive action (free, remove) is behind an explicit confirmation
dialog. REVIEW-tier processes get an extra warning because they're uncertain.
"""

from __future__ import annotations

import threading
from tkinter import messagebox

import customtkinter as ctk
import psutil

from core.scanner import scan, ScannedProcess
from core.classifier import Tier
from core.watchdog import Watchdog
from core import bloatware

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

TIER_COLOR = {
    Tier.CRITICAL: "#8a8f98",   # grey — untouchable
    Tier.REVIEW: "#d9a441",     # amber — caution
    Tier.SAFE: "#4caf72",       # green — ok to free
}


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RAM Optimizer — Memory Freeer")
        self.geometry("1040x680")
        self.minsize(900, 560)

        self.watchdog = Watchdog(poll_interval=3.0)
        self.watchdog.start()

        self._scanned: list[ScannedProcess] = []
        self._bloat: list[bloatware.BloatApp] = []

        # --- system memory header (visible above every tab) ---------------
        self.mem_header = ctk.CTkFrame(self)
        self.mem_header.pack(fill="x", padx=12, pady=(12, 0))

        self.mem_label = ctk.CTkLabel(
            self.mem_header, text="System memory: …",
            font=("", 14, "bold"), anchor="w",
        )
        self.mem_label.pack(side="left", padx=12, pady=8)

        self.mem_pct_label = ctk.CTkLabel(
            self.mem_header, text="", font=("", 20, "bold"), anchor="e",
        )
        self.mem_pct_label.pack(side="right", padx=12)

        self.mem_bar = ctk.CTkProgressBar(self.mem_header, width=360, height=16)
        self.mem_bar.pack(side="right", padx=12, pady=8)
        self.mem_bar.set(0)

        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=12)
        self.tab_proc = self.tabs.add("Processes")
        self.tab_blocked = self.tabs.add("Blocked")
        self.tab_opt = self.tabs.add("Optimize Windows")
        self.tab_log = self.tabs.add("Activity")

        self._build_processes_tab()
        self._build_blocked_tab()
        self._build_optimize_tab()
        self._build_log_tab()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(300, self.refresh_processes)
        self._update_memory()  # start the live memory meter

    # ------------------------------------------------------------------ MEMORY METER
    def _update_memory(self):
        """Refresh the system-memory header, then reschedule itself (2s)."""
        try:
            vm = psutil.virtual_memory()
            used_gb = (vm.total - vm.available) / (1024 ** 3)
            total_gb = vm.total / (1024 ** 3)
            pct = vm.percent  # percent used

            self.mem_label.configure(
                text=f"System memory: {used_gb:.1f} GB used of {total_gb:.1f} GB"
            )
            self.mem_pct_label.configure(text=f"{pct:.0f}%")
            self.mem_bar.set(pct / 100.0)

            # Colour the bar + percent by pressure: green < 70, amber < 85, red otherwise.
            if pct < 70:
                color = "#4caf72"
            elif pct < 85:
                color = "#d9a441"
            else:
                color = "#d9534f"
            self.mem_bar.configure(progress_color=color)
            self.mem_pct_label.configure(text_color=color)
        except Exception:
            self.mem_label.configure(text="System memory: unavailable")

        self.after(2000, self._update_memory)

    # ------------------------------------------------------------------ PROCESSES
    def _build_processes_tab(self):
        bar = ctk.CTkFrame(self.tab_proc)
        bar.pack(fill="x", padx=8, pady=8)

        self.btn_scan = ctk.CTkButton(bar, text="Rescan", command=self.refresh_processes)
        self.btn_scan.pack(side="left", padx=4)

        self.filter_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(
            bar, variable=self.filter_var,
            values=["All", "Safe to free", "Review", "Critical"],
            command=lambda _=None: self._render_processes(),
        ).pack(side="left", padx=4)

        self.btn_free_safe = ctk.CTkButton(
            bar, text="Free all SAFE idle processes",
            fg_color="#2e7d4f", hover_color="#256b43",
            command=self.free_all_safe,
        )
        self.btn_free_safe.pack(side="left", padx=4)

        self.summary = ctk.CTkLabel(bar, text="Scanning…")
        self.summary.pack(side="right", padx=8)

        # legend
        legend = ctk.CTkFrame(self.tab_proc)
        legend.pack(fill="x", padx=8)
        for tier, text in [
            (Tier.SAFE, "Safe to free — idle, no window, no I/O"),
            (Tier.REVIEW, "Review — uncertain, you decide (never auto-killed)"),
            (Tier.CRITICAL, "Critical — protected, cannot be freed"),
        ]:
            ctk.CTkLabel(
                legend, text="  ● " + text, text_color=TIER_COLOR[tier],
                anchor="w",
            ).pack(side="left", padx=6, pady=2)

        self.proc_scroll = ctk.CTkScrollableFrame(self.tab_proc)
        self.proc_scroll.pack(fill="both", expand=True, padx=8, pady=8)

    def refresh_processes(self):
        self.summary.configure(text="Scanning…")
        self.btn_scan.configure(state="disabled")

        def work():
            data = scan(0.4)
            self._scanned = data
            self.after(0, self._render_processes)
            self.after(0, lambda: self.btn_scan.configure(state="normal"))

        threading.Thread(target=work, daemon=True).start()

    def _render_processes(self):
        for w in self.proc_scroll.winfo_children():
            w.destroy()

        flt = self.filter_var.get()
        rows = self._scanned
        if flt != "All":
            rows = [r for r in rows if r.tier.value == flt]

        total_ram = sum(r.ram_mb for r in self._scanned)
        safe_ram = sum(r.ram_mb for r in self._scanned if r.tier == Tier.SAFE)
        n_safe = sum(1 for r in self._scanned if r.tier == Tier.SAFE)
        self.summary.configure(
            text=f"{len(self._scanned)} processes · {total_ram:,.0f} MB · "
                 f"{n_safe} safe to free (~{safe_ram:,.0f} MB)"
        )

        # header
        hdr = ctk.CTkFrame(self.proc_scroll, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 4))
        for text, w in [("Process", 220), ("RAM", 90), ("CPU", 70),
                        ("Tier", 110), ("Why", 300), ("", 90)]:
            ctk.CTkLabel(hdr, text=text, width=w, anchor="w",
                         font=("", 12, "bold")).pack(side="left", padx=2)

        for r in rows[:400]:
            row = ctk.CTkFrame(self.proc_scroll)
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text=r.name[:30], width=220, anchor="w").pack(side="left", padx=2)
            ctk.CTkLabel(row, text=f"{r.ram_mb:,.0f} MB", width=90, anchor="w").pack(side="left", padx=2)
            ctk.CTkLabel(row, text=f"{r.cpu_percent:.0f}%", width=70, anchor="w").pack(side="left", padx=2)
            ctk.CTkLabel(row, text=r.tier.value, width=110, anchor="w",
                         text_color=TIER_COLOR[r.tier]).pack(side="left", padx=2)
            ctk.CTkLabel(row, text=r.reason[:46], width=300, anchor="w",
                         text_color="#9aa0a6").pack(side="left", padx=2)
            if r.tier == Tier.CRITICAL:
                ctk.CTkLabel(row, text="protected", width=90,
                             text_color=TIER_COLOR[Tier.CRITICAL]).pack(side="left", padx=2)
            else:
                ctk.CTkButton(
                    row, text="Free", width=84,
                    fg_color="#2e7d4f" if r.tier == Tier.SAFE else "#9a6b1f",
                    hover_color="#256b43" if r.tier == Tier.SAFE else "#855c1a",
                    command=lambda rr=r: self.free_one(rr),
                ).pack(side="left", padx=2)

    def free_one(self, r: ScannedProcess):
        warn = ""
        if r.tier == Tier.REVIEW:
            warn = ("\n\n⚠ This process is in the REVIEW tier — the app is "
                    "NOT confident it's idle. Free it only if you know what "
                    "it is.")
        if not messagebox.askyesno(
            "Confirm free",
            f"Free '{r.name}' (pid {r.pid}, {r.ram_mb:,.0f} MB)?\n\n"
            f"It will be terminated and the watchdog will re-kill it if it "
            f"respawns, until you release it or reboot.{warn}",
        ):
            return
        ok, msg = self.watchdog.block_and_kill(r.pid, r.name)
        if not ok:
            messagebox.showerror("Could not free", msg)
        self.refresh_processes()
        self._render_blocked()
        self._render_log()

    def free_all_safe(self):
        safe = [r for r in self._scanned if r.tier == Tier.SAFE]
        if not safe:
            messagebox.showinfo("Nothing to free", "No SAFE idle processes found.")
            return
        ram = sum(r.ram_mb for r in safe)
        names = "\n".join(f"  • {r.name}  ({r.ram_mb:,.0f} MB)" for r in safe[:25])
        more = f"\n  …and {len(safe) - 25} more" if len(safe) > 25 else ""
        if not messagebox.askyesno(
            "Confirm free all SAFE",
            f"Free {len(safe)} idle background processes (~{ram:,.0f} MB)?\n\n"
            f"{names}{more}\n\nEach will be blocked by the watchdog until "
            f"released or reboot.",
        ):
            return
        for r in safe:
            self.watchdog.block_and_kill(r.pid, r.name)
        self.refresh_processes()
        self._render_blocked()
        self._render_log()

    # ------------------------------------------------------------------ BLOCKED
    def _build_blocked_tab(self):
        top = ctk.CTkFrame(self.tab_blocked)
        top.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(
            top,
            text="Processes freed this session. The watchdog re-kills active "
                 "ones if they respawn. Toggle any back on to let it run. "
                 "All blocks clear on reboot.",
            anchor="w", wraplength=900, justify="left",
        ).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Refresh", command=self._render_blocked).pack(side="right", padx=4)

        self.blocked_scroll = ctk.CTkScrollableFrame(self.tab_blocked)
        self.blocked_scroll.pack(fill="both", expand=True, padx=8, pady=8)

    def _render_blocked(self):
        for w in self.blocked_scroll.winfo_children():
            w.destroy()
        entries = self.watchdog.entries()
        if not entries:
            ctk.CTkLabel(self.blocked_scroll,
                         text="No processes blocked this session.").pack(pady=20)
            return
        for e in entries:
            row = ctk.CTkFrame(self.blocked_scroll)
            row.pack(fill="x", pady=2)
            status = "Blocking" if e.active else "Released"
            color = "#d9a441" if e.active else "#4caf72"
            ctk.CTkLabel(row, text=e.display_name, width=240, anchor="w").pack(side="left", padx=4)
            ctk.CTkLabel(row, text=status, width=100, anchor="w",
                         text_color=color).pack(side="left", padx=4)
            ctk.CTkLabel(row, text=f"re-killed {e.kill_count}×", width=120,
                         anchor="w", text_color="#9aa0a6").pack(side="left", padx=4)
            if e.active:
                ctk.CTkButton(row, text="Allow to run (release)", width=180,
                              fg_color="#2e7d4f", hover_color="#256b43",
                              command=lambda n=e.display_name: self._release(n)
                              ).pack(side="left", padx=4)
            else:
                ctk.CTkButton(row, text="Block again", width=180,
                              fg_color="#9a6b1f", hover_color="#855c1a",
                              command=lambda n=e.display_name: self._reactivate(n)
                              ).pack(side="left", padx=4)

    def _release(self, name: str):
        self.watchdog.release(name)
        self._render_blocked()
        self._render_log()

    def _reactivate(self, name: str):
        self.watchdog.reactivate(name)
        self._render_blocked()
        self._render_log()

    # ------------------------------------------------------------------ OPTIMIZE
    def _build_optimize_tab(self):
        top = ctk.CTkFrame(self.tab_opt)
        top.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(
            top,
            text="Optional. Lists ONLY recognizable preinstalled Store apps "
                 "(bloatware). Regular software is never shown. Removal is "
                 "per-app and reversible — reinstall from the Store anytime.",
            anchor="w", wraplength=880, justify="left",
        ).pack(side="left", padx=4)
        self.btn_bloat = ctk.CTkButton(top, text="Scan for bloatware",
                                       command=self.scan_bloatware)
        self.btn_bloat.pack(side="right", padx=4)

        self.bloat_scroll = ctk.CTkScrollableFrame(self.tab_opt)
        self.bloat_scroll.pack(fill="both", expand=True, padx=8, pady=8)

    def scan_bloatware(self):
        self.btn_bloat.configure(state="disabled", text="Scanning…")

        def work():
            apps = bloatware.list_bloatware()
            self._bloat = apps
            self.after(0, self._render_bloat)
            self.after(0, lambda: self.btn_bloat.configure(
                state="normal", text="Scan for bloatware"))

        threading.Thread(target=work, daemon=True).start()

    def _render_bloat(self):
        for w in self.bloat_scroll.winfo_children():
            w.destroy()
        if not self._bloat:
            ctk.CTkLabel(
                self.bloat_scroll,
                text="No recognizable preinstalled bloatware found "
                     "(or PowerShell/Appx unavailable).",
            ).pack(pady=20)
            return
        for a in self._bloat:
            row = ctk.CTkFrame(self.bloat_scroll)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=a.display_label, width=260, anchor="w").pack(side="left", padx=4)
            ctk.CTkLabel(row, text=a.family_name[:40], width=360, anchor="w",
                         text_color="#9aa0a6").pack(side="left", padx=4)
            ctk.CTkButton(row, text="Uninstall", width=120,
                          fg_color="#9a3b3b", hover_color="#852f2f",
                          command=lambda app=a: self._uninstall(app)
                          ).pack(side="left", padx=4)

    def _uninstall(self, app: bloatware.BloatApp):
        if not messagebox.askyesno(
            "Confirm uninstall",
            f"Uninstall '{app.display_label}' for your user account?\n\n"
            f"Package: {app.family_name}\n\n"
            f"This is reversible — you can reinstall it from the Microsoft "
            f"Store later.",
        ):
            return

        def work():
            ok, msg = bloatware.uninstall(app)
            self.watchdog._log(
                f"Uninstall '{app.display_label}': "
                f"{'OK' if ok else 'FAILED'} — {msg}"
            )
            self.after(0, lambda: (
                messagebox.showinfo("Uninstall", msg) if ok
                else messagebox.showerror("Uninstall failed", msg)
            ))
            self.after(0, self.scan_bloatware)
            self.after(0, self._render_log)

        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------------ LOG
    def _build_log_tab(self):
        top = ctk.CTkFrame(self.tab_log)
        top.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(top, text="Everything this app did, newest last.",
                     anchor="w").pack(side="left", padx=4)
        ctk.CTkButton(top, text="Refresh", command=self._render_log).pack(side="right", padx=4)
        self.log_box = ctk.CTkTextbox(self.tab_log)
        self.log_box.pack(fill="both", expand=True, padx=8, pady=8)

    def _render_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        for ev in self.watchdog.audit_log():
            self.log_box.insert(
                "end", f"[{ev.when:%H:%M:%S}] {ev.message}\n"
            )
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    # ------------------------------------------------------------------ lifecycle
    def _on_close(self):
        self.watchdog.stop()
        self.destroy()


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
