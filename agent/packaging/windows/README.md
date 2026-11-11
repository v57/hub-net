# hub-net on Windows

hub-net runs on Windows 11 and Windows Server 2022 or later (amd64 and arm64) as a LocalSystem service
with WireGuardNT. The package holds `hub-net.exe`; WireGuardNT's `wireguard.dll` for the same
architecture goes next to it, from the official signed release (`wireguard-nt-<version>.zip` on
<https://download.wireguard.com/wireguard-nt/>, `bin\<arch>\wireguard.dll`).

> **Status: not supported yet.** On Windows 11 arm64 the service installs, starts, serves
> `\\.\pipe\hub-net-command` with its DACL, stops and uninstalls; split DNS (NRPT), the port-list
> filters (WFP) and the pipe ACLs pass their suites. The WireGuardNT adapter and its routes haven't run
> against the driver yet, and no Windows device has joined a hub, so [`PLATFORMS.md`](../../../PLATFORMS.md)
> still lists Windows as planned.

## Install

From an elevated PowerShell:

```powershell
New-Item -ItemType Directory -Force "$env:ProgramFiles\hub-net"
Copy-Item hub-net.exe, wireguard.dll "$env:ProgramFiles\hub-net\"
# Optional: a local group whose members may drive hub-net (Hub on Windows runs as one)
net localgroup hub-net /add
net localgroup hub-net $env:USERNAME /add
& "$env:ProgramFiles\hub-net\hub-net.exe" -socket-group hub-net service install
```

`service install` registers the `hub-net` service (automatic start, restart on failure) with the
flags given before `service`, and starts it. It checks that `wireguard.dll` sits next to
`hub-net.exe`.

- State: `%ProgramData%\hub-net`, and the device key `%ProgramData%\hub\device.key`. The service
  makes both directories private (SYSTEM and Administrators only) at every start.
- Log: `%ProgramData%\hub-net\hub-net.log`, replaced at each start; start and stop failures also go
  to the Application event log (source `hub-net`).
- Commands: `\\.\pipe\hub-net-command`. Its DACL admits SYSTEM, elevated Administrators and the
  `-socket-group` group; the CLI (`hub-net join …`, `hub-net list`) runs from an elevated shell or
  as a member of that group.
- Services on the device prove themselves to the agent over `\\.\pipe\hub-net-agent` (the Hub
  machine's agent) and one pipe per membership.

## What it changes on the system

- One WireGuardNT adapter per Hub (`hubnet0`, `hubnet1`, …) with only `100.96.0.0/11` and
  `fd48:5542:4e45::/48` routes; the agent refuses to start a Hub whose overlay route another
  interface already has. The adapter goes away when the service stops.
- WFP filters in a dynamic session (provider "hub-net"): inbound TCP and UDP to the overlay
  addresses is dropped except the device's port list allows it. They go away with the process.
- One NRPT rule per Hub for `.hub.invalid`, pointing at the membership's resolver on a loopback
  address `127.72.x.y:53`. The service removes it on stop, and replaces a rule a crash left behind
  at the next start.

## Update and uninstall

```powershell
& "$env:ProgramFiles\hub-net\hub-net.exe" service stop
Copy-Item hub-net.exe "$env:ProgramFiles\hub-net\" -Force
& "$env:ProgramFiles\hub-net\hub-net.exe" service start

& "$env:ProgramFiles\hub-net\hub-net.exe" service uninstall   # stops and removes the service
```

Uninstalling leaves `%ProgramData%\hub-net` (the memberships and keys); delete it to forget them.
