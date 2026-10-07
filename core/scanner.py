"""
Process scanner.

Collects per-process signals using psutil and (on Windows) enumerates visible
top-level windows via the Win32 API so we can tell GUI apps from pure
background processes.

CPU% and I/O rate are RATES, so the scanner samples twice with a short gap:
the first pass primes psutil's internal counters, the second reads the delta.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import psutil

from .classifier import ProcSignals, Classification, classify, Tier


# --- Visible-window detection (Windows only) --------------------------------

def _pids_with_visible_windows() -> set[int]:
    """Return the set of PIDs that own at least one visible top-level window."""
    pids: set[int] = set()
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        EnumWindows = user32.EnumWindows
        EnumWindowsProc = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )
        GetWindowThreadProcessId = user32.GetWindowThreadProcessId
        IsWindowVisible = user32.IsWindowVisible

        def _callback(hwnd, _lparam):
            if IsWindowVisible(hwnd):
                pid = wintypes.DWORD()
                GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    pids.add(pid.value)
            return True

        EnumWindows(EnumWindowsProc(_callback), 0)
    except Exception:
        # Non-Windows or API unavailable: treat as "unknown" (empty set).
        pass
    return pids


# --- One scanned process ----------------------------------------------------

@dataclass
class ScannedProcess:
    signals: ProcSignals
    classification: Classification

    # convenience accessors used by the GUI
    @property
    def pid(self) -> int:
        return self.signals.pid

    @property
    def name(self) -> str:
        return self.signals.name

    @property
    def ram_mb(self) -> float:
        return self.signals.ram_mb

    @property
    def cpu_percent(self) -> float:
        return self.signals.cpu_percent

    @property
    def tier(self) -> Tier:
        return self.classification.tier

    @property
    def reason(self) -> str:
        return self.classification.reason


def scan(sample_interval: float = 0.4) -> list[ScannedProcess]:
    """
    Scan all processes and classify them.

    sample_interval: seconds between the two sampling passes used to compute
    CPU% and I/O rate. Larger = more accurate, slower.
    """
    windowed = _pids_with_visible_windows()

    # Pass 1: prime cpu_percent and record I/O counters.
    first_io: dict[int, int] = {}
    procs: dict[int, psutil.Process] = {}
    for p in psutil.process_iter(["pid"]):
        try:
            p.cpu_percent(None)  # prime
            procs[p.pid] = p
            io = _safe_io_total(p)
            if io is not None:
                first_io[p.pid] = io
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(sample_interval)

    results: list[ScannedProcess] = []
    for pid, p in procs.items():
        try:
            with p.oneshot():
                name = p.name()
                cpu = p.cpu_percent(None)
                mem = p.memory_info().rss / (1024 * 1024)
                try:
                    username = p.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = None

            io_now = _safe_io_total(p)
            if io_now is not None and pid in first_io:
                io_rate = max(0, io_now - first_io[pid]) / sample_interval
            else:
                io_rate = 0.0

            sig = ProcSignals(
                pid=pid,
                name=name,
                cpu_percent=cpu,
                ram_mb=mem,
                io_rate_bytes=io_rate,
                has_visible_window=pid in windowed,
                is_user_session=username is not None,
                username=username,
            )
            results.append(ScannedProcess(sig, classify(sig)))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by RAM descending — most impactful first.
    results.sort(key=lambda s: s.ram_mb, reverse=True)
    return results


def _safe_io_total(p: psutil.Process) -> int | None:
    """Total I/O bytes (read+write+other) for a process, or None if unavailable."""
    try:
        io = p.io_counters()
        total = io.read_bytes + io.write_bytes
        # Windows exposes 'other_bytes'; guard in case it's absent.
        total += getattr(io, "other_bytes", 0)
        return total
    except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
        return None
