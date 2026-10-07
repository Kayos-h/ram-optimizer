"""
Process classifier.

Turns raw per-process signals into one of three tiers:

    CRITICAL  -> never touch (OS/security/self). Not killable by any path.
    REVIEW    -> uncertain. NEVER auto-killed. Shown to the user to decide.
    SAFE      -> confidently idle userland background work. Eligible to kill,
                 but STILL only killed when the user confirms in the GUI.

Design principle (from the user's constraints): when uncertain, FLAG for
review rather than kill. So the SAFE tier is deliberately narrow — a process
only lands there when multiple signals agree it is idle and non-essential.

Nothing in this module kills anything. It only labels. Termination happens in
watchdog.py, and only on explicit user action.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .critical import is_critical


class Tier(str, Enum):
    CRITICAL = "Critical"       # never touch
    REVIEW = "Review"           # uncertain -> user decides, never auto-kill
    SAFE = "Safe to free"       # confidently idle background process


# Signals we feed the classifier for one process.
@dataclass
class ProcSignals:
    pid: int
    name: str
    cpu_percent: float          # recent CPU usage (0..100 * cores)
    ram_mb: float               # resident memory in MB
    io_rate_bytes: float        # bytes/sec of disk+other I/O since last sample
    has_visible_window: bool    # owns a visible top-level window
    is_user_session: bool       # runs in the interactive user's session
    username: str | None        # owning user (None if unknown)


# Thresholds — tuned conservatively. A process must be BELOW all activity
# thresholds to even be considered idle.
CPU_IDLE_THRESHOLD = 1.0            # percent
IO_IDLE_THRESHOLD = 50 * 1024       # 50 KB/s — anything busier is "doing I/O"


@dataclass
class Classification:
    tier: Tier
    reason: str                 # human-readable justification shown in the GUI


def classify(sig: ProcSignals) -> Classification:
    """Classify one process from its signals. Pure function, no side effects."""

    # 1. Hard floor: critical OS/security/self processes are untouchable.
    if is_critical(sig.name):
        return Classification(Tier.CRITICAL, "Critical OS / security / app process")

    # 2. Processes owned by SYSTEM / LOCAL SERVICE / NETWORK SERVICE are
    #    service-level. We never auto-classify these as safe — too risky.
    svc_accounts = {"system", "local service", "network service"}
    owner = (sig.username or "").split("\\")[-1].strip().lower()
    if owner in svc_accounts or sig.username is None:
        return Classification(
            Tier.REVIEW,
            "System/service-owned — review before freeing",
        )

    # 3. Actively doing visible user-facing work -> never a kill candidate.
    if sig.has_visible_window:
        return Classification(
            Tier.REVIEW,
            "Has a visible window — looks user-facing, review first",
        )

    # 4. Actively computing -> active, not idle.
    if sig.cpu_percent > CPU_IDLE_THRESHOLD:
        return Classification(
            Tier.REVIEW,
            f"Using CPU ({sig.cpu_percent:.1f}%) — may be working, review first",
        )

    # 5. Actively doing I/O -> active, not idle.
    if sig.io_rate_bytes > IO_IDLE_THRESHOLD:
        return Classification(
            Tier.REVIEW,
            f"Active disk/network I/O ({sig.io_rate_bytes/1024:.0f} KB/s) — review first",
        )

    # 6. Reached here: userland, no visible window, ~0 CPU, ~0 I/O.
    #    This is a genuinely idle background process in the user's session.
    #    SAFE to offer for freeing — but still user-confirmed in the GUI.
    return Classification(
        Tier.SAFE,
        "Idle background process (no window, ~0% CPU, no I/O)",
    )
