"""
Bloatware detection + removal (OPT-IN, confirmation-gated).

Scope is deliberately narrow to be safe:
  * Only Microsoft Store / provisioned APPX packages are listed (via
    Get-AppxPackage). We never touch classic desktop (Win32) software.
  * From those, only packages matching a known "preinstalled, non-essential"
    allowlist are shown as removable. Everything else — and anything we can't
    positively identify — is simply not offered for removal.
  * Removal runs Remove-AppxPackage for the CURRENT USER only (no -AllUsers),
    which is reversible: the user can reinstall from the Store.
  * Nothing is removed without an explicit per-item confirmation in the GUI.

If PowerShell or the Appx cmdlets are unavailable, the feature degrades to an
empty list rather than erroring.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

# Known preinstalled, non-essential consumer apps safe to offer for removal.
# Matched as a case-insensitive substring against the package family name.
# Intentionally EXCLUDES anything system-ish: Store, .NET, VCLibs, framework
# packages, Edge/WebView, Xbox identity, etc.
REMOVABLE_PATTERNS = {
    "king.com": "Candy Crush (King games)",
    "candycrush": "Candy Crush",
    "bytedance": "TikTok",
    "spotifyab.spotifymusic": "Spotify (preinstalled)",
    "facebook": "Facebook",
    "4df9e0f8.netflix": "Netflix (preinstalled)",
    "disney": "Disney+ (preinstalled)",
    "amazon.com.amazon": "Amazon (preinstalled)",
    "microsoft.bingweather": "MSN Weather",
    "microsoft.bingnews": "Microsoft News",
    "microsoft.getdevices": "Phone Link promo",
    "microsoft.gethelp": "Get Help",
    "microsoft.microsoftsolitairecollection": "Microsoft Solitaire",
    "microsoft.people": "People",
    "microsoft.windowsfeedbackhub": "Feedback Hub",
    "microsoft.zunemusic": "Groove Music",
    "microsoft.zunevideo": "Movies & TV",
    "microsoft.mixedreality.portal": "Mixed Reality Portal",
    "microsoft.skypeapp": "Skype (preinstalled)",
    "microsoft.todos": "Microsoft To Do",
    "clipchamp": "Clipchamp",
    "linkedinforwindows": "LinkedIn",
    "microsoft.549981c3f5f10": "Cortana",
}

# Never offer these for removal even if a loose pattern matched.
PROTECTED_SUBSTRINGS = (
    "windowsstore", "storepurchaseapp", "desktopappinstaller",
    "vclibs", "framework", "runtime", "dotnet", ".net",
    "webview", "edge", "ui.xaml", "nativ", "winappruntime",
    "accountscontrol", "sechealthui", "windows.immersivecontrolpanel",
    "windowsterminal", "windows.photos", "windowscalculator",
    "windowscamera", "windowsnotepad", "windowssoundrecorder",
)


@dataclass
class BloatApp:
    package_full_name: str
    family_name: str
    display_label: str


def _run_powershell(script: str, timeout: int = 60) -> str | None:
    """Run a PowerShell snippet, return stdout or None on failure."""
    try:
        proc = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script,
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def list_bloatware() -> list[BloatApp]:
    """Return removable preinstalled Store apps for the current user."""
    script = (
        "Get-AppxPackage | "
        "Select-Object Name, PackageFullName, PackageFamilyName | "
        "ConvertTo-Json -Compress"
    )
    out = _run_powershell(script)
    if not out:
        return []

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]

    found: list[BloatApp] = []
    seen: set[str] = set()
    for pkg in data:
        family = (pkg.get("PackageFamilyName") or "").strip()
        full = (pkg.get("PackageFullName") or "").strip()
        name = (pkg.get("Name") or "").strip()
        if not family or not full:
            continue

        low = (family + " " + name).lower()

        # Hard protection: skip anything system/framework-ish.
        if any(bad in low for bad in PROTECTED_SUBSTRINGS):
            continue

        label = None
        for pat, friendly in REMOVABLE_PATTERNS.items():
            if pat in low:
                label = friendly
                break
        if label is None:
            continue  # not on our known-removable allowlist -> not offered

        if family in seen:
            continue
        seen.add(family)
        found.append(BloatApp(full, family, label))

    found.sort(key=lambda a: a.display_label.lower())
    return found


def uninstall(app: BloatApp) -> tuple[bool, str]:
    """
    Remove a single preinstalled app for the current user.
    Caller MUST have obtained explicit user confirmation first.
    Reversible: the user can reinstall from the Microsoft Store.
    """
    # Re-check protection at the moment of removal (defense in depth).
    low = app.family_name.lower()
    if any(bad in low for bad in PROTECTED_SUBSTRINGS):
        return False, "Refused: protected system package."

    script = (
        f"Remove-AppxPackage -Package '{app.package_full_name}' "
        f"-ErrorAction Stop"
    )
    out = _run_powershell(script, timeout=120)
    if out is None:
        return False, (
            "Uninstall failed (may need Administrator, or the app is in use)."
        )
    return True, f"Removed {app.display_label}."
