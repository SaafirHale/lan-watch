# Portfolio entry (draft)

Draft for `src/content/projects.ts` on saafirhale.com, in the shape of the site's `Project` type. Not yet added to the site. Every claim below can be checked against this repo; no real MAC, IP or network name appears in it or in the screenshot.

```ts
{
  slug: "lan-watch",
  category: "security",
  title: "lan-watch",
  blurb: "Passive-first home network monitor: device inventory, new-device toasts and ARP-spoofing detection, fenced so it can only ever touch one confirmed private subnet.",
  body: [
    "lan-watch keeps an inventory of every device on one home network and raises a Windows toast when an unknown one joins. Each device is stored in SQLite with its MAC, IP history, vendor from an offline IEEE OUI lookup (longest prefix across MA-L, MA-M and MA-S), hostname from DHCP, mDNS, NetBIOS or the router, first and last seen, a label and a known flag. A local dashboard shows the device list, a timeline and a one-click Mark as known.",
    "The laptop it runs on also carries a corporate VPN and DNS-filtering client, so the safety model comes first. The network is confirmed once by typing its subnet; only RFC 1918 ranges of /22 or smaller qualify, and confirmation is refused while a VPN adapter is up. Every run re-checks the interface, subnet, gateway, Windows network profile and VPN state and, when anything differs, logs a skipped run before the neighbor table is even read, so nothing from another network is ever stored. Active probes need an authorization object that only the safety module can mint, and every target passes a hard in-subnet check before a packet leaves.",
    "Default runs send nothing: they read the Windows neighbor cache, with optional listeners for mDNS, SSDP, DHCP and NetBIOS broadcasts. Light active discovery is a second opt-in, using Windows' own SendARP at 10 requests per second, so it needs no Npcap and no admin rights. Port checks are limited to an opt-in top-20 TCP connect test on a single chosen device.",
    "Detections cover new devices, IP conflicts and gateway ARP changes, including the router's MAC answering for a second IP, the classic spoofing signature. Phones that randomise their Wi-Fi MAC are recognised by the locally administered bit, explained in the dashboard and summarised in one quiet notice instead of an intruder alert. A rotated private MAC that announces a known hostname is linked to the earlier device but never trusted automatically, because hostnames are spoofable.",
    "Everything from the network is treated as hostile input: the DNS, DHCP and NetBIOS parsers are bounds-checked against truncation and compression loops, names are sanitised, the dashboard renders with textContent only, and toast text is XML-escaped outside any code path. The dashboard binds to 127.0.0.1 and rejects foreign Host headers, cross-origin writes and requests without a CSRF token. The runtime is the Python standard library plus tools that ship with Windows, covered by 77 unit tests on synthetic ARP-table, adapter and wire-format packet fixtures.",
  ],
  stack: ["Python 3.12 (stdlib only)", "SQLite", "PowerShell", "Windows iphlpapi (SendARP)", "WinRT toasts", "Task Scheduler", "pytest"],
  links: [{ label: "Source", href: "https://github.com/SaafirHale/lan-watch" }],
  status: "live",
}
```

Notes for publishing:

- The source is public at https://github.com/SaafirHale/lan-watch, so `status` is `"live"`.
- `docs/dashboard.png` is the dashboard in privacy view (MACs cut to the vendor half, IPs to the last octet, network name hidden). It is safe to use as the project image.
