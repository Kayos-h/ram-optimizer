"""
RAM Optimizer — entry point.

Detects whether the app is running with Administrator rights (needed to
terminate some processes and to uninstall preinstalled apps) and warns the
user if not, without blocking — many userland processes can still be freed
without elevation.
"""

from __future__ import annotations

import ctypes
import sys


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> None:
    if sys.platform != "win32":
        print("This tool targets Windows 10/11 only.")
        sys.exit(1)

    if not is_admin():
        print(
            "NOTE: not running as Administrator.\n"
            "You can still free most user background processes, but some "
            "system-owned processes and bloatware removal will need elevation.\n"
            "To get full control, close this and run again as Administrator.\n"
        )

    # Import after the platform check so a non-Windows run fails cleanly.
    from app import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
