"""
Critical-process allowlist.

This is the SAFETY FLOOR of the whole app. Any process whose name (or whose
owning path) matches here is classified Critical and can NEVER be terminated,
suspended, or added to the watchdog blocklist by any code path in this app.

The list is intentionally conservative: core Windows kernel/session processes,
the Windows security stack (Defender), and common third-party security agents.
When in doubt, a process is NOT added here (so it falls to the classifier,
which flags unknowns for user review rather than killing them).
"""

from __future__ import annotations

# Core Windows OS / session processes. Killing any of these can bluescreen,
# log the user out, or make the machine unbootable.
_CRITICAL_OS = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",          # session manager
    "csrss.exe",         # client/server runtime (kills -> BSOD)
    "wininit.exe",       # windows init
    "winlogon.exe",      # logon
    "services.exe",      # service control manager
    "lsass.exe",         # local security authority (kills -> forced reboot)
    "lsaiso.exe",        # credential guard
    "fontdrvhost.exe",
    "dwm.exe",           # desktop window manager
    "svchost.exe",       # service host (many critical services live here)
    "taskhostw.exe",
    "sihost.exe",        # shell infrastructure
    "ctfmon.exe",        # text input
    "explorer.exe",      # the shell itself
    "runtimebroker.exe",
    "spoolsv.exe",       # print spooler (safe-ish, but keep conservative)
    "conhost.exe",
    "dllhost.exe",
    "wudfhost.exe",
    "audiodg.exe",       # audio device graph
    "memory compression",
    "secure system",
    "idle",
}

# Windows security stack + common endpoint-protection agents.
_CRITICAL_SECURITY = {
    "msmpeng.exe",       # Defender antimalware engine
    "nissrv.exe",        # Defender network inspection
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "mpcmdrun.exe",
    "smartscreen.exe",
    "sense.exe",         # Defender for Endpoint
    # Common third-party security agents (defensive; harmless if absent):
    "ccsvchst.exe",      # Norton/Symantec
    "mcshield.exe",      # McAfee
    "avp.exe",           # Kaspersky
    "avguard.exe",       # Avira
    "avgnt.exe",
    "bdagent.exe",       # Bitdefender
    "ekrn.exe",          # ESET
    "cbdefense.exe",     # Carbon Black
    "csfalconservice.exe",  # CrowdStrike
    "sentinelagent.exe",    # SentinelOne
}

# The user running the app themselves — our own process must never be killed.
_SELF = {
    "python.exe",
    "pythonw.exe",
    "py.exe",
    "kiro-cli.exe",      # agent host (do not offer to kill the runtime)
    "kirocrew.exe",
}

CRITICAL_NAMES = _CRITICAL_OS | _CRITICAL_SECURITY | _SELF


def is_critical(proc_name: str | None) -> bool:
    """Return True if a process name is on the never-touch allowlist."""
    if not proc_name:
        # No name == we can't identify it == treat as critical (do not kill).
        return True
    return proc_name.strip().lower() in CRITICAL_NAMES
