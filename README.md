# AnonSurf-Windows

A Windows replacement for the abandoned 2020 AnonSurf GUI, with a
modern Qt 6 interface and notification-area controls.
It starts an **official Tor Expert Bundle** daemon, verifies that Tor is working, runs a small local HTTP-to-SOCKS bridge, and only then enables the current user's Windows proxy. It does **not** include a Tor executable.
This is **not a VPN** and does not transparently capture every connection. Only programs that honor the Windows user proxy are routed. UDP, QUIC, games, launchers, services, and programs with independent proxy settings can bypass it. Use official Tor Browser when the goal is anonymous web browsing.

## Setup
Download the current **Windows x86_64 Tor Expert Bundle** from:
   `https://www.torproject.org/download/tor/`
Extract the archive.
Run `run.bat` and select the extracted `tor.exe`.

Python 3.11 or newer is recommended. `run.bat` installs the Qt 6 runtime when
it is missing. To install it manually:
`py -3 -m pip install -r requirements.txt`

## Build a standalone Windows executable
Run `build_exe.bat`. The result is written to `dist\AnonSurfSafe.exe`.
The standalone application still does not bundle Tor. Select the official `tor.exe` on first launch.

## Recovery without the application
If Windows cannot access the internet after a forced shutdown:
1. Open **Settings → Network & internet → Proxy**.
2. Turn off **Use a proxy server**.
3. Run `restore_proxy.bat`, or reopen AnonSurf Safe and use **Restore Windows proxy**.

Configuration and recovery data are stored under:
`%LOCALAPPDATA%\AnonSurfSafe`

## Modified/replacement status

This project was written as a replacement and does not reuse the original application's Python source or bundled executable.
hence why the original github is not linked. 
