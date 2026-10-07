# RAM Optimizer — Memory Freeer

A Windows 10/11 tool that frees up RAM by terminating genuinely idle background
processes, with a safety-first design: it never auto-kills anything uncertain,
never touches critical OS/security processes, and keeps every destructive
action behind an explicit confirmation.

## Requirements

- Windows 10 or 11 (64-bit)
- Python 3.10+ (built and tested on 3.14)
- Dependencies: `pip install -r requirements.txt`

## Run

```powershell
python main.py
```

For full control (freeing system-owned processes, removing preinstalled apps),
run from an **Administrator** PowerShell. Without elevation you can still free
most of your own background processes.

## How it decides what is safe to kill

Every process is sorted into one of three tiers:

| Tier | Meaning | Can be freed? |
|------|---------|---------------|
| **Critical** | Core OS, Windows/third-party security, and this app's own runtime | **Never** — hard-blocked in code |
| **Review** | Uncertain: owns a window, uses CPU, does I/O, or is service-owned | Only by you, with an extra warning. **Never auto-killed.** |
| **Safe to free** | Userland, no visible window, ~0% CPU, no I/O — a genuinely idle background process | Yes, after you confirm |

The rule from the spec is honored literally: **when uncertain, flag for review
rather than kill.** The "Safe" tier is deliberately narrow — several signals
must agree a process is idle before it lands there.

## The watchdog (restart prevention)

When you free a process it is added to an in-memory **session blocklist** and a
background thread re-kills it if it respawns. This is the reversible approach:

- **No registry edits, no service disabling, no renaming executables.**
- The blocklist lives only in memory — it clears when you **close the app** or
  **reboot**, so nothing is permanently suppressed.
- Each blocked item has a toggle: **Allow to run (release)** stops re-killing
  it; **Block again** re-enables it.

## Optimize Windows (bloatware)

Optional and opt-in. It lists **only recognizable preinstalled Microsoft Store
apps** (Candy Crush, preinstalled Spotify/Netflix, Groove, etc.). Regular
desktop software is never shown. Removal is **per-app, confirmation-gated, and
reversible** (reinstall from the Store). System/framework packages are
double-protected and never offered.

## Project layout

```
main.py             entry point + admin detection
app.py              customtkinter GUI (Processes / Blocked / Optimize / Activity)
core/
  critical.py       never-touch allowlist (OS + security + self)
  classifier.py     tier logic (pure, no side effects)
  scanner.py        psutil-based signal collection + window detection
  watchdog.py       session blocklist + re-kill-on-respawn thread
  bloatware.py      Store-app detection + confirmation-gated uninstall
```

## Safety summary

- Critical processes are rejected at **three** layers (classifier, watchdog
  block, terminate helper).
- Nothing is terminated or removed without a confirmation dialog.
- Uncertain processes are flagged, never auto-killed.
- All actions are recorded in the **Activity** tab's audit log.
