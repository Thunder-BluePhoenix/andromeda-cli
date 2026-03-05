# Andromeda Setup Guide

Complete guide for installing, configuring, and running Andromeda Dashboard.

---

## Table of Contents

1. [Install the CLI](#1-install-the-cli)
2. [Run the Setup Wizard](#2-run-the-setup-wizard)
3. [Manual Configuration](#3-manual-configuration)
4. [Audio & Camera Backends (Linux)](#4-audio--camera-backends-linux)
5. [Screen Capture Backends (Linux)](#5-screen-capture-backends-linux)
6. [Internet Access Options](#6-internet-access-options)
7. [Permissions](#7-permissions)
8. [All CLI Commands](#8-all-cli-commands)
9. [Config File Reference](#9-config-file-reference)
10. [File Locations](#10-file-locations)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Install the CLI

### Windows

```powershell
irm https://raw.githubusercontent.com/Thunder-BluePhoenix/andromeda-cli/main/scripts/install.ps1 | iex
```

Installs `andromeda.exe` to `%LOCALAPPDATA%\Andromeda\` and adds it to your user `PATH`.

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/Thunder-BluePhoenix/andromeda-cli/main/scripts/install.sh | bash
```

Installs `andromeda` to `/usr/local/bin` (falls back to `~/.local/bin` if no write access).

After install, open a new terminal and verify:

```bash
andromeda version
```

---

## 2. Run the Setup Wizard

The fastest way to get started:

```bash
andromeda setup
```

The wizard walks you through every step interactively. You can re-run it at any time — it remembers your previous choices.

### Wizard Steps

#### Step 1 — Dashboard Binary

Checks whether the dashboard binary is already downloaded.

- If missing, offers to download from GitHub automatically.
- You can also point to a custom binary path with `andromeda config binary <PATH>`.

#### Step 2 — API Key

The API key protects your dashboard from unauthorized access.

- If you already have a key, it is shown and kept.
- You can generate a fresh key or keep the existing one.
- The key is a 28-character random alphanumeric string.

> To change the key at any time: `andromeda apikey new` or `andromeda apikey set <KEY>`

#### Step 3 — Internet Access

Choose how you want to reach the dashboard from the internet.

| Option | Description |
|--------|-------------|
| Cloudflare Tunnel | Free HTTPS URL, no account required. Recommended for most users. |
| IPv6 | Zero-config if your network has a global IPv6 address. |
| Router port forward | Forward port `3000` in your router admin panel. |
| Skip | Local network access only. |

You can set this up (or change it) at any time after setup — see [Internet Access Options](#6-internet-access-options).

#### Step 4 — Audio / Camera Backend *(Linux only)*

Controls how audio and camera hardware is accessed. See [Audio & Camera Backends](#4-audio--camera-backends-linux) for a full comparison.

#### Step 5 — Screen Capture Backend *(Linux only)*

Controls how the screen is captured for streaming. See [Screen Capture Backends](#5-screen-capture-backends-linux) for a full comparison.

#### Step 6 — Permissions

Checks that the required OS permissions are in place:

- **macOS**: Screen Recording, Accessibility, Camera, Microphone (TCC). The wizard can open System Settings for you.
- **Linux**: `video` group (camera), `audio` group (microphone), UFW firewall rules.
- **Windows**: Administrator rights for some features.

#### Step 7 — Start Now

Optionally starts the dashboard immediately and shows all access URLs.

---

## 3. Manual Configuration

If you prefer not to use the wizard, configure everything with `andromeda config`:

```bash
andromeda config show             # show all current settings
andromeda config port 8080        # change port (default: 3000)
andromeda config binary /path/to/andromeda-dashboard  # custom binary path
andromeda config audio subprocess  # set audio backend (Linux)
andromeda config screen xcb        # set screen backend (Linux)
```

Then start the dashboard:

```bash
andromeda start
andromeda open    # open in browser
```

---

## 4. Audio & Camera Backends (Linux)

On Linux, ALSA (the audio layer) calls `select()` internally, which crashes if any file descriptor number ≥ 1024. Modern Linux systems commonly have 500k+ open FD limits, which makes this easy to trigger. The `audio_backend` setting controls how this is handled.

Set with:

```bash
andromeda config audio <mode>
andromeda restart
```

### Modes

#### `cap` *(default)*

Caps `RLIMIT_NOFILE` to 1024 at startup. All FDs opened by the process stay below 1024, so ALSA `select()` is always safe.

- **Pros**: Simple, zero overhead, works everywhere.
- **Cons**: Limits the process to ~1009 simultaneous open connections.
- **Best for**: Most users — the connection limit is rarely reached in practice.

```bash
andromeda config audio cap
```

#### `subprocess`

Audio and camera operations run in an isolated child process with a clean FD table. The main dashboard process has no FD limit.

- **Pros**: Unlimited FDs in the main process; strongest isolation.
- **Cons**: Slight latency overhead from IPC.
- **Best for**: Servers that handle many simultaneous connections.

```bash
andromeda config audio subprocess
```

#### `pipewire`

Uses PipeWire's JACK-compatible interface instead of ALSA. PipeWire uses `epoll` (not `select`), so FD numbers above 1024 are fine.

- **Pros**: No FD limit; lower latency than subprocess; integrates natively with PipeWire desktop audio.
- **Cons**: Requires PipeWire + `pipewire-jack` (the wizard auto-installs these via `apt`).
- **Best for**: Modern desktops (Ubuntu 22.04+, Fedora 34+) already running PipeWire.

```bash
andromeda config audio pipewire
```

To install PipeWire manually if not using the wizard:

```bash
sudo apt install pipewire pipewire-alsa pipewire-jack wireplumber
```

#### `guard`

Checks FD safety per-call. If the current FD numbers are ≥ 924, that audio/camera request is skipped silently.

- **Pros**: No FD cap, no subprocess.
- **Cons**: Audio/camera may silently drop under high FD load.
- **Best for**: Situations where audio is optional and you want to avoid any restrictions.

```bash
andromeda config audio guard
```

#### `off`

Disables audio and camera entirely. All `/api/audio/*` and `/api/camera/*` endpoints return `503 Service Unavailable`.

- **Pros**: No ALSA dependency at all; headless/server use.
- **Best for**: Servers where you only need terminal, file editor, or screen sharing.

```bash
andromeda config audio off
```

### Comparison

| Mode | FD Limit | Subprocess | Requires PipeWire | Best For |
|------|----------|------------|-------------------|----------|
| `cap` | ~1009 FDs | No | No | Most users (default) |
| `subprocess` | Unlimited | Yes | No | High-connection servers |
| `pipewire` | Unlimited | Yes | Yes | Modern PipeWire desktops |
| `guard` | Unlimited | No | No | Optional audio with no restrictions |
| `off` | N/A | No | No | Headless / server |

---

## 5. Screen Capture Backends (Linux)

The `screen_backend` setting controls how the screen is captured for the MJPEG stream, screen snapshots, and WebRTC video.

Set with:

```bash
andromeda config screen <mode>
andromeda restart
```

### Wayland Note (Ubuntu 22.04+, Ubuntu 24.04)

Ubuntu 22.04+ uses GNOME with Wayland by default. XCB's `GetImage` call returns a black frame on Wayland because the Wayland compositor does not expose its framebuffer through XWayland.

**Fix**: install `grim`, a lightweight Wayland screenshot tool:

```bash
sudo apt install grim
```

The dashboard auto-detects Wayland (`WAYLAND_DISPLAY` or `XDG_SESSION_TYPE=wayland`) and uses `grim` automatically when it is installed. No config change needed. The setup wizard (Step 5) also detects Wayland and offers to install `grim` for you.

`grim` works on any Wayland compositor that supports `zwlr-screencopy`, or via `xdg-desktop-portal` (which covers GNOME 42+, i.e. Ubuntu 22.04 and later).

### Modes

#### `xcb` *(default, recommended)*

Uses `x11rb` (pure-Rust XCB protocol client). On X11: connects directly to the X server and captures the root window. On Wayland: automatically delegates to `grim` if installed.

- **Pros**: FD-safe at any FD count; no C library dependencies; works in the main process.
- **On Wayland**: requires `grim` installed (`sudo apt install grim`).
- **Best for**: All Linux users — handles both X11 and Wayland automatically.

```bash
andromeda config screen xcb
```

#### `xlib`

Uses the `screenshots` crate (Xlib). Spawns a subprocess for isolation to avoid the FD_SETSIZE crash.

- **Pros**: Widest compatibility.
- **Cons**: Subprocess overhead; also broken on Wayland (same black-screen issue).
- **Best for**: Fallback only.

```bash
andromeda config screen xlib
```

### Comparison

| Mode | X11 | Wayland | FD-Safe | Subprocess |
|------|-----|---------|---------|------------|
| `xcb` | Yes | Yes (needs `grim`) | Yes | No (MJPEG); Yes (WebRTC) |
| `xlib` | Yes | No (black screen) | No (direct) | Yes |

> **Note on WebRTC**: Both modes use a subprocess for WebRTC screen sharing. `ANDROMEDA_SCREEN_BACKEND` is inherited by the subprocess, so Wayland + `grim` works end-to-end.

---

## 6. Internet Access Options

### Cloudflare Tunnel *(recommended)*

```bash
andromeda tunnel cloudflare
```

Opens a free HTTPS tunnel at `https://random-name.trycloudflare.com`. No sign-up, no data limit, works behind NAT/firewalls. The URL changes each time the tunnel is started.

- `cloudflared` is auto-downloaded if not already installed.
- Keep the terminal open while the tunnel is active.
- Share the URL with anyone who needs access.

### IPv6 *(zero-config)*

```bash
andromeda ipv6
```

If your machine has a global IPv6 address (common on ISPs that support IPv6), the dashboard is already reachable at `http://[your-ipv6]:3000` from anywhere on the internet — no tunnel, no router config needed.

```bash
andromeda status    # shows IPv6 URL if available
```

### ngrok

```bash
andromeda tunnel ngrok
```

Requires the [ngrok](https://ngrok.com) binary installed and a free account with an auth token configured (`ngrok config add-authtoken <token>`).

### Router Port Forwarding *(manual)*

In your router's admin panel, forward TCP port `3000` (or your configured port) to your machine's LAN IP address. Then the dashboard is reachable at `http://<your-public-ip>:3000`.

```bash
andromeda status    # shows your public IP and LAN IP
```

### UPnP *(automatic)*

The dashboard attempts automatic UPnP port forwarding on startup with a 3-second timeout, then falls back gracefully if not supported. No action needed — it just works on UPnP-enabled routers.

### Expose a Specific Port

To route external traffic for any port through the dashboard's IPv6 connection:

```bash
andromeda expose -p 5000                     # expose port 5000 via IPv6
andromeda expose -p 5000 -u 127.0.0.1:5000  # explicit target
andromeda expose -p 5000 -n "my-service"    # with a label
andromeda exposed                            # list all exposed ports
andromeda unexpose -p 5000                  # stop exposing
```

---

## 7. Permissions

### macOS

The dashboard needs:
- **Screen Recording** — for screen capture and sharing
- **Accessibility** — for input simulation (keyboard/mouse)
- **Camera** — for webcam access
- **Microphone** — for audio streaming

Go to **System Settings → Privacy & Security** and grant each permission to `andromeda-dashboard`. The setup wizard offers to open this panel for you.

### Linux

**Groups:**

```bash
sudo usermod -aG video $USER    # camera access
sudo usermod -aG audio $USER    # microphone access
```

Log out and back in (or run `newgrp video`) for group changes to take effect.

**Firewall (UFW):**

```bash
sudo ufw allow 3000/tcp    # open dashboard port
# The wizard opens port_range:port_range+9/tcp for port fallback support
```

**System Libraries:**

The `doctor` command checks for required shared libraries:

```bash
andromeda doctor
```

On Ubuntu/Debian, install common missing deps:

```bash
sudo apt install libxdotool-dev libasound2 libv4l-dev libxtst6 libxfixes3
# For WebRTC (if using Linux WebRTC AV):
sudo apt install libopus0 libvpx7   # or libvpx9 on Ubuntu 24.04+
# For PipeWire audio mode:
sudo apt install pipewire pipewire-alsa pipewire-jack wireplumber libjack-jackd2-0
```

### Windows

Some features (admin mode, firewall rules) may require running as Administrator.

```bash
andromeda config show    # shows sudo/admin mode status
```

---

## 8. All CLI Commands

### Install & Update

| Command | Description |
|---------|-------------|
| `andromeda install` | Download the dashboard binary from GitHub releases |
| `andromeda install --repo org/repo` | Install from a custom GitHub releases repo |
| `andromeda update` | Update to latest release; skips if already current; auto-restarts if running |
| `andromeda self-update` | Update the CLI binary itself |
| `andromeda setup` | Interactive first-time (or re-run) setup wizard |

### Process Management

| Command | Description |
|---------|-------------|
| `andromeda start` | Start dashboard in the background (detached) |
| `andromeda start -d` | Start and detach immediately without streaming logs |
| `andromeda stop` | Stop the running dashboard gracefully |
| `andromeda restart` | Kill + restart the dashboard (applies config changes) |
| `andromeda killall` | Kill all `andromeda-dashboard` processes on any port (force kill) |
| `andromeda status` | Show PID, version, and all access URLs |

### Dashboard Access

| Command | Description |
|---------|-------------|
| `andromeda open` | Open the dashboard in the default browser |
| `andromeda logs` | Show last 50 lines of dashboard logs |
| `andromeda logs -f` | Follow logs in real time (`tail -f` style) |
| `andromeda logs -n 200` | Show last N lines |

### API Key

| Command | Description |
|---------|-------------|
| `andromeda apikey` | Show current key and access URL |
| `andromeda apikey new` | Generate a new random 28-char key and apply it |
| `andromeda apikey set <KEY>` | Set a specific key |

### Internet Tunnels

| Command | Description |
|---------|-------------|
| `andromeda tunnel cloudflare` | Open a free Cloudflare Tunnel (no account) |
| `andromeda tunnel ngrok` | Open an ngrok tunnel (requires account) |
| `andromeda ipv6` | Show global IPv6 address and direct URL |
| `andromeda expose -p PORT` | Expose a port via IPv6 |
| `andromeda exposed` | List all exposed ports |
| `andromeda unexpose -p PORT` | Stop exposing a port |

### Configuration

| Command | Description |
|---------|-------------|
| `andromeda config show` | Print all config values |
| `andromeda config port <N>` | Set dashboard port (default: `3000`) |
| `andromeda config binary <PATH>` | Set path to dashboard binary |
| `andromeda config audio <MODE>` | Set audio/camera backend — Linux only |
| `andromeda config screen <MODE>` | Set screen capture backend — Linux only |

**Audio modes**: `cap` \| `guard` \| `subprocess` \| `pipewire` \| `off`

**Screen modes**: `xcb` \| `xlib`

### Diagnostics & Cleanup

| Command | Description |
|---------|-------------|
| `andromeda version` | Show CLI and dashboard versions, check for updates |
| `andromeda doctor` | Full health check: binary, config, port, firewall, libraries, tools |
| `andromeda purge` | Delete the dashboard binary (keeps config and API key) |
| `andromeda purge -y` | Same, skip confirmation |
| `andromeda uninstall` | Remove dashboard binary and all config/data |
| `andromeda uninstall -y` | Same, skip confirmation |
| `andromeda uninstall --with-cli` | Also remove the CLI binary itself |

---

## 9. Config File Reference

**Location:**

| Platform | Path |
|----------|------|
| Linux | `~/.config/andromeda/config.toml` |
| macOS | `~/Library/Application Support/andromeda/config.toml` |
| Windows | `%APPDATA%\andromeda\config.toml` |

**All fields:**

```toml
# API key used to authenticate with the dashboard.
# Auto-generated on first install. Change with: andromeda apikey new
api_key = "your28charkey"

# Port the dashboard listens on.
# If the port is busy, the dashboard tries port+1 through port+9 automatically.
# Default: 3000
port = 3000

# Path to the andromeda-dashboard binary.
# Auto-set by andromeda install. Only change if using a custom binary.
binary_path = "/home/user/.local/share/Andromeda/andromeda-dashboard"

# GitHub repo used for install/update.
# Default: "Thunder-BluePhoenix/andromeda-releases"
dashboard_repo = "Thunder-BluePhoenix/andromeda-releases"

# Installed version tag (e.g. "v1.4.0").
# Managed automatically — do not edit manually.
installed_version = "v1.4.0"

# Enable admin/sudo mode for privileged operations.
# Default: false
sudo = false

# Audio and camera backend. Linux only.
# Options: cap | guard | subprocess | pipewire | off
# Default: cap
audio_backend = "cap"

# Screen capture backend. Linux only.
# Options: xcb | xlib
# Default: xcb
screen_backend = "xcb"
```

All fields are optional — missing fields use their defaults. The file is created automatically on first run.

---

## 10. File Locations

### Config Directory

| Platform | Path |
|----------|------|
| Linux | `~/.config/andromeda/` |
| macOS | `~/Library/Application Support/andromeda/` |
| Windows | `%APPDATA%\andromeda\` |

| File | Purpose |
|------|---------|
| `config.toml` | All configuration (port, key, binary path, backends) |
| `dashboard.pid` | PID of the currently running dashboard process |
| `dashboard.log` | Dashboard stdout/stderr output |
| `dashboard.log.old` | Previous log file (rotated when `dashboard.log` exceeds 10 MB) |

### Binary Directory

| Platform | Path |
|----------|------|
| Linux | `~/.local/share/Andromeda/andromeda-dashboard` |
| macOS | `~/Library/Application Support/Andromeda/andromeda-dashboard` |
| Windows | `%LOCALAPPDATA%\Andromeda\andromeda-dashboard.exe` |

---

## 11. Troubleshooting

### Dashboard won't start

```bash
andromeda doctor       # full health check
andromeda logs         # check for startup errors
andromeda status       # verify process is running
```

Common causes:
- Binary not downloaded → `andromeda install`
- Port already in use → `andromeda config port 3001`
- Missing permissions (Linux) → see [Permissions](#7-permissions)

### Can't reach dashboard from another device

```bash
andromeda status       # shows all URLs including LAN IP
```

- Make sure firewall allows the port: `sudo ufw allow 3000/tcp`
- Try a tunnel: `andromeda tunnel cloudflare`

### Audio / Camera not working (Linux)

1. Check group membership: `groups` — you need `audio` and `video`
2. Add yourself: `sudo usermod -aG audio,video $USER` then log out/in
3. Check libraries: `andromeda doctor`
4. Try a different backend: `andromeda config audio subprocess && andromeda restart`

### Screen capture broken (Linux)

- Make sure `DISPLAY` is set: `echo $DISPLAY` should show `:0` or similar
- Verify xcb mode: `andromeda config screen xcb && andromeda restart`
- If running headless (no X11), screen capture is not available

### High FD count / ALSA crash (Linux)

Symptom: `*** buffer overflow detected ***` or `Aborted (core dumped)` in logs.

```bash
andromeda config audio cap && andromeda restart    # safest fix
# or for no connection limit:
andromeda config audio subprocess && andromeda restart
```

### "Dashboard is running — restart to apply"

After any `config` change, restart to apply:

```bash
andromeda restart
```

### Check for updates

```bash
andromeda version         # show versions + update availability
andromeda update          # update dashboard binary
andromeda self-update     # update the CLI itself
```
