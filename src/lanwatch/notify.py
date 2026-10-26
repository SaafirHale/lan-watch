"""Windows toast notifications through the WinRT API that ships with PowerShell 5.1.

Titles and bodies can contain hostnames taken from network packets, so they
are XML-escaped here and handed to a fixed PowerShell script as base64 in an
environment variable. No text from the network is ever spliced into code.
"""

from __future__ import annotations

import base64
import os
import subprocess
from xml.sax.saxutils import escape, quoteattr

from .detect import Alert

# PowerShell's registered AppUserModelID, so the toast has a sender without
# registering a new app on the system.
APP_ID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"

_SHOW = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xmlText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:LANWATCH_TOAST_XML))
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xmlText)
$toast = New-Object Windows.UI.Notifications.ToastNotification $doc
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:LANWATCH_TOAST_APPID).Show($toast)
"""

MAX_TOASTS_PER_RUN = 3


def toast_xml(title: str, body: str, launch_url: str | None = None) -> str:
    launch = f" launch={quoteattr(launch_url)} activationType=\"protocol\"" if launch_url else ""
    return (
        f"<toast{launch}><visual><binding template=\"ToastGeneric\">"
        f"<text>{escape(title[:120])}</text><text>{escape(body[:400])}</text>"
        f"<text placement=\"attribution\">lan-watch</text>"
        f"</binding></visual></toast>"
    )


def show_toast(title: str, body: str, launch_url: str | None = None) -> bool:
    env = dict(os.environ)
    env["LANWATCH_TOAST_XML"] = base64.b64encode(toast_xml(title, body, launch_url).encode("utf-8")).decode("ascii")
    env["LANWATCH_TOAST_APPID"] = APP_ID
    encoded = base64.b64encode(_SHOW.encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            env=env, capture_output=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def plan_toasts(alerts: list[Alert]) -> list[tuple[str, str]]:
    """Most severe first, at most MAX_TOASTS_PER_RUN; the rest collapse into one summary."""
    order = {"critical": 0, "warning": 1, "info": 2}
    ranked = sorted(alerts, key=lambda a: order.get(a.severity, 3))
    shown = [(a.title, a.body) for a in ranked[:MAX_TOASTS_PER_RUN]]
    rest = ranked[MAX_TOASTS_PER_RUN:]
    if rest:
        shown[-1] = ("More network alerts", f"{len(rest) + 1} more alerts this run. Open the dashboard for details.")
    return shown


def deliver(alerts: list[Alert], dashboard_url: str | None = None, sender=show_toast) -> int:
    sent = 0
    for title, body in plan_toasts(alerts):
        if sender(title, body, dashboard_url):
            sent += 1
    return sent
