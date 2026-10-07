"""
Watchdog — the reversible "prevent restart until reboot" mechanism.

How it works (the SAFE approach the user chose):

  * When the user frees a process, its name is added to an in-memory
    SESSION BLOCKLIST and the process is terminated.
  * A background thread periodically rescans. If any blocklisted process has
    respawned, it is terminated again.
  * The user can RELEASE any item (toggle it back on) — it leaves the
    blocklist and will no longer be re-killed.
  * The blocklist lives only in memory. On app close OR system reboot it is
    gone, so nothing is permanently suppressed. This is deliberate: we never
    edit the registry, disable services, or rename executables.

Safety invariants:
  * Critical processes are rejected by block() — they can never be blocked.
  * Termination is graceful first (terminate -> wait -> kill as last resort).
  * All actions are logged to an in-memory audit list the GUI can display.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

import psutil

from .critical import is_critical


@dataclass
class BlockEntry:
    name: str                       # process image name, lowercased
    display_name: str               # original-case name for the UI
    blocked_at: datetime
    kill_count: int = 0             # how many times we've killed it (incl. respawns)
    active: bool = True             # False == released by the user
    last_action: str = "blocked"


@dataclass
class AuditEvent:
    when: datetime
    message: str


class Watchdog:
    def __init__(self, poll_interval: float = 3.0):
        self._poll_interval = poll_interval
        self._lock = threading.RLock()
        self._blocklist: dict[str, BlockEntry] = {}   # keyed by lowercase name
        self._audit: list[AuditEvent] = []
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # --- audit -------------------------------------------------------------
    def _log(self, msg: str) -> None:
        with self._lock:
            self._audit.append(AuditEvent(datetime.now(), msg))
            # keep the audit bounded
            if len(self._audit) > 500:
                self._audit = self._audit[-500:]

    def audit_log(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._audit)

    # --- blocklist queries -------------------------------------------------
    def entries(self) -> list[BlockEntry]:
        with self._lock:
            return list(self._blocklist.values())

    def is_blocked(self, name: str) -> bool:
        with self._lock:
            e = self._blocklist.get(name.lower())
            return bool(e and e.active)

    # --- the two user actions ---------------------------------------------
    def block_and_kill(self, pid: int, name: str) -> tuple[bool, str]:
        """
        Add a process to the session blocklist and terminate it.
        Returns (success, message). Refuses critical processes.
        """
        if is_critical(name):
            return False, f"Refused: {name} is a protected critical process."

        key = name.lower()
        with self._lock:
            entry = self._blocklist.get(key)
            if entry is None:
                entry = BlockEntry(
                    name=key, display_name=name, blocked_at=datetime.now()
                )
                self._blocklist[key] = entry
            entry.active = True
            entry.last_action = "blocked"

        ok, msg = self._terminate_pid(pid, name)
        if ok:
            with self._lock:
                self._blocklist[key].kill_count += 1
            self._log(f"Blocked and freed '{name}' (pid {pid}). {msg}")
        else:
            self._log(f"Block requested for '{name}' but termination failed: {msg}")
        return ok, msg

    def release(self, name: str) -> None:
        """Toggle a blocked process back on — stop re-killing it this session."""
        key = name.lower()
        with self._lock:
            e = self._blocklist.get(key)
            if e:
                e.active = False
                e.last_action = "released"
        self._log(f"Released '{name}' — it may run again this session.")

    def reactivate(self, name: str) -> None:
        """Re-enable blocking for an item the user previously released."""
        key = name.lower()
        if is_critical(name):
            return
        with self._lock:
            e = self._blocklist.get(key)
            if e:
                e.active = True
                e.last_action = "blocked"
        self._log(f"Re-enabled blocking for '{name}'.")

    # --- termination helper ------------------------------------------------
    def _terminate_pid(self, pid: int, name: str) -> tuple[bool, str]:
        """Graceful terminate, escalate to kill only if needed."""
        if is_critical(name):
            return False, "critical process, refused"
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return True, "already gone"
        try:
            p.terminate()
            try:
                p.wait(timeout=3)
                return True, "terminated gracefully"
            except psutil.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)
                return True, "force-killed"
        except psutil.AccessDenied:
            return False, "access denied (try running as Administrator)"
        except psutil.NoSuchProcess:
            return True, "exited"
        except Exception as e:  # noqa: BLE001 — surface any OS error to the UI
            return False, f"error: {e}"

    # --- background watchdog loop -----------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="watchdog", daemon=True
        )
        self._thread.start()
        self._log("Watchdog started.")

    def stop(self) -> None:
        self._stop.set()
        self._log("Watchdog stopping — all blocks cleared on exit.")

    def _loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            self._sweep()

    def _sweep(self) -> None:
        """Re-kill any active-blocklist process that has respawned."""
        with self._lock:
            active_names = {
                e.name for e in self._blocklist.values() if e.active
            }
        if not active_names:
            return

        for p in psutil.process_iter(["pid", "name"]):
            try:
                nm = (p.info["name"] or "").lower()
            except Exception:
                continue
            if nm in active_names and not is_critical(nm):
                pid = p.info["pid"]
                ok, msg = self._terminate_pid(pid, nm)
                if ok and "already gone" not in msg and "exited" not in msg:
                    with self._lock:
                        self._blocklist[nm].kill_count += 1
                    self._log(f"Watchdog re-killed respawned '{nm}' (pid {pid}).")
