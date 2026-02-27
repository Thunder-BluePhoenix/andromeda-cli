# Andromeda CLI — Complete Command Reference

> Every command, subcommand, flag, and option in one place.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Global Usage](#global-usage)
- [Lifecycle Commands](#lifecycle-commands)
  - [self-update](#self-update)
  - [version](#version)
  - [setup](#setup)
  - [install](#install)
  - [update](#update)
- [Dashboard Process](#dashboard-process)
  - [start](#start)
  - [stop](#stop)
  - [restart](#restart)
  - [killall](#killall)
  - [status](#status)
  - [open](#open)
- [Monitoring](#monitoring)
  - [logs](#logs)
  - [doctor](#doctor)
- [API Key](#api-key)
  - [apikey](#apikey)
- [Internet Access](#internet-access)
  - [ipv6](#ipv6)
  - [tunnel](#tunnel)
  - [expose](#expose)
  - [exposed](#exposed)
  - [unexpose](#unexpose)
- [Configuration](#configuration)
  - [config show](#config-show)
  - [config port](#config-port)
  - [config binary](#config-binary)
  - [config audio](#config-audio)
- [Removal](#removal)
  - [purge](#purge)
  - [uninstall](#uninstall)
- [Config File Reference](#config-file-reference)

---

## Quick Start

```bash
andromeda setup           # first-time wizard (recommended)
andromeda install         # download dashboard binary
andromeda start           # start and attach to logs
andromeda start -d        # start in background (detached)
andromeda status          # show URLs and PID
andromeda stop            # stop the dashboard
```

---

## Global Usage

```
andromeda <COMMAND> [OPTIONS]
andromeda --help
andromeda --version
andromeda <COMMAND> --help
```

Every command supports `--help` for inline documentation.

---

## Lifecycle Commands

### `self-update`

Update the Andromeda CLI binary itself in-place. Detects your platform automatically,
downloads the correct binary from GitHub, and replaces the running CLI.

```bash
andromeda self-update
```

- No flags or arguments
- Works on Windows, Linux (x86_64 / aarch64), macOS (Intel / Apple Silicon)
- On Windows: renames the old binary to `.bak` and schedules cleanup

---

### `version`

Show the installed CLI version, the installed dashboard version, and check if a newer
release is available on GitHub.

```bash
andromeda version
andromeda version --repo <OWNER/REPO>
```

| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | `Thunder-BluePhoenix/andromeda-releases` | GitHub releases repo to check |

---

### `setup`

Interactive first-time setup wizard. Walks through all configuration options with
descriptions and defaults. The same settings can be changed individually afterwards
using `andromeda config <option>`.

```bash
andromeda setup
andromeda setup --repo <OWNER/REPO>
```

**Wizard steps:**

| Step | What it does |
|------|-------------|
| 1 — Binary | Checks if the dashboard binary exists; offers to download it |
| 2 — API key | Shows current key or generates a new one |
| 3 — Internet access | Cloudflare tunnel / IPv6 / router port-forward |
| 4 — Audio backend | Choose ALSA handling mode *(Linux only)* |
| 5 — Permissions | Admin/sudo mode toggle |
| 6 — Start | Optionally start the dashboard immediately |

---

### `install`

Download the dashboard binary from GitHub releases for your platform.

```bash
andromeda install
andromeda install --repo <OWNER/REPO>
```

| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | `Thunder-BluePhoenix/andromeda-releases` | GitHub releases repo |

- Stops any running dashboard before overwriting the binary
- Saves the installed version to config for `andromeda version` to report

---

### `update`

Smart update — checks the latest release and downloads it only if a newer version
is available. Safe to run on a schedule.

```bash
andromeda update
andromeda update --repo <OWNER/REPO>
```

- If already on latest: prints "Already up to date" and exits
- If an update is available: downloads and replaces the binary (stops dashboard first)

---

## Dashboard Process

### `start`

Start the dashboard. By default **attaches to the log stream** so you can see startup
output and live logs. Press `Ctrl+C` to stop.

```bash
andromeda start
andromeda start -d          # detached (background)
andromeda start --detach    # same as -d
```

| Flag | Short | Description |
|------|-------|-------------|
| `--detach` | `-d` | Start in background, print URLs, then return to shell |

**What happens on start:**

1. Checks that the binary exists (suggests `andromeda install` if not)
2. Kills any stale process from the PID file
3. Spawns the dashboard (stdout + stderr → log file)
4. Waits up to 15 seconds for the startup banner
5. Reads the actual bound port from the log (handles auto-port-increment)
6. Prints all access URLs (localhost, LAN, IPv6, internet)
7. Checks and configures firewall rules (UFW on Linux, Windows Firewall)
8. Attaches to live logs (unless `-d`)

---

### `stop`

Stop the running dashboard gracefully.

```bash
andromeda stop
```

- Reads the PID file, sends a termination signal, clears the PID file
- If the process is not running, reports the stale PID and clears it

---

### `restart`

Stop the dashboard (if running) then start it again in detached mode.

```bash
andromeda restart
```

- Equivalent to `andromeda stop && andromeda start -d`
- Safe to run even if the dashboard is not currently running

---

### `killall`

Kill **every** `andromeda-dashboard` process on the system — including orphans not
tracked by the PID file (leftover from `cargo run`, crashes, or multiple invocations).

```bash
andromeda killall
```

- Uses `SIGKILL` on Linux/macOS (cannot be ignored, works on stopped/frozen processes)
- Uses `taskkill /F` on Windows
- Excludes the CLI process itself
- Reports only the count of processes that actually died
- Fixes "Text file busy" errors when reinstalling after a crash

---

### `status`

Show whether the dashboard is running and all its access URLs.

```bash
andromeda status
```

**Example output:**

```
  Status         :  running (PID 12345)
  Localhost      :  http://localhost:3000?api_key=abc123
  LAN            :  http://192.168.1.5:3000?api_key=abc123
  IPv6           :  http://[2409:4091:...]:3000?api_key=abc123
  Internet       :  http://49.37.51.228:3000 (forward port 3000)
```

---

### `open`

Open the dashboard in the system's default browser.

```bash
andromeda open
```

- Reads the port and API key from config
- Opens `http://localhost:<port>?api_key=<key>`
- Works on Linux (xdg-open), macOS (open), Windows (start)

---

## Monitoring

### `logs`

View the dashboard log. By default shows the last 50 lines.

```bash
andromeda logs
andromeda logs -f           # follow live (like tail -f)
andromeda logs -n 100       # show last 100 lines
andromeda logs -f -n 0      # follow from current end (no history)
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--follow` | `-f` | false | Stream new lines live (Ctrl+C to stop) |
| `--lines` | `-n` | 50 | Number of recent lines to show |

**Log file location:**

| Platform | Path |
|----------|------|
| Linux / macOS | `~/.config/andromeda/dashboard.log` |
| Windows | `%APPDATA%\andromeda\dashboard.log` |

The log rotates automatically when it exceeds 10 MB (old log saved as `dashboard.log.old`).

---

### `doctor`

Run a full health check and report any problems.

```bash
andromeda doctor
```

**Checks performed:**

| Check | What it verifies |
|-------|-----------------|
| Binary | Dashboard binary exists and is executable |
| Config | Config file is valid TOML with expected fields |
| Process | Whether the dashboard is currently running |
| Port | Whether the configured port is reachable |
| Firewall | UFW / Windows Firewall rules for the dashboard port |
| Tools | Optional tools: `cloudflared`, `ngrok`, `pw-cli` (PipeWire) |

---

## API Key

### `apikey`

Manage the API key that protects dashboard access.

```bash
andromeda apikey            # same as: andromeda apikey show
andromeda apikey show       # print current key and full access URL
andromeda apikey new        # generate a new random 32-character key
andromeda apikey set <KEY>  # set a specific key you provide
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `show` | Print the current API key and the full `localhost` URL with it |
| `new` | Generate a new cryptographically random key and save it |
| `set <KEY>` | Set your own key (any non-empty string) |

> **Note:** Changing the key takes effect on the next `andromeda restart`.

---

## Internet Access

### `ipv6`

Print your machine's global IPv6 address and the direct internet URL for the dashboard.
IPv6 requires **no router configuration** — every device gets a real public address.

```bash
andromeda ipv6
```

**Example output:**

```
  IPv6 address   :  2409:4091:1031:640a:29df:7877:3bcd:ff18
  Dashboard URL  :  http://[2409:4091:1031:640a:29df:7877:3bcd:ff18]:3000?api_key=...
  Anyone on the internet can open this URL directly (no port forwarding needed).
```

---

### `tunnel`

Open an internet tunnel to make the dashboard accessible without any router or firewall
configuration, even behind CGNAT or a corporate network.

```bash
andromeda tunnel cloudflare    # free, no account needed
andromeda tunnel ngrok         # requires a free ngrok account
```

**Subcommands:**

| Subcommand | Tool needed | Account | Cost |
|------------|-------------|---------|------|
| `cloudflare` | `cloudflared` (auto-installed if absent) | None | Free |
| `ngrok` | `ngrok` (must be installed manually) | Free account | Free tier |

---

### `expose`

Expose any local port to the internet via IPv6 — no router setup needed. Andromeda
runs a transparent TCP proxy: internet traffic hits the IPv6 port and is forwarded
to your local service.

```bash
andromeda expose -p 8080                        # expose localhost:8080
andromeda expose -p 8080 -u 127.0.0.1:8080     # explicit target
andromeda expose -p 9000 -u 192.168.1.5:3000   # forward to another LAN device
andromeda expose -p 8080 -n "My Web App"        # with a label
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--port` | `-p` | **Yes** | IPv6 port to listen on (what the outside world connects to) |
| `--url` | `-u` | No | Target address to forward to (default: `127.0.0.1:<port>`) |
| `--name` | `-n` | No | Human-readable label shown in the exposed ports list |

**How it works:**

```
Browser (anywhere on internet)
  │  connects to [your-ipv6]:8080
  ▼
Andromeda proxy  ──►  127.0.0.1:8080  (your local app)
```

The proxy is fully transparent — HTTP, WebSockets, gRPC, raw TCP all work unchanged.

---

### `exposed`

List all currently exposed ports with their IPv6 access URLs.

```bash
andromeda exposed
```

**Example output:**

```
  PORT    TARGET             IPv6 ACCESS URL
  8080    127.0.0.1:8080     http://[2409:4091:...]:8080
  3001    127.0.0.1:3001     http://[2409:4091:...]:3001
```

---

### `unexpose`

Stop exposing a port and shut down its proxy.

```bash
andromeda unexpose -p 8080
andromeda unexpose --port 8080
```

| Flag | Short | Description |
|------|-------|-------------|
| `--port` | `-p` | The IPv6 port to stop exposing |

---

## Configuration

All config commands read from and write to `~/.config/andromeda/config.toml`
(Linux/macOS) or `%APPDATA%\andromeda\config.toml` (Windows).

### `config show`

Print all current configuration values.

```bash
andromeda config show
```

**Example output:**

```
  Config file    :  /home/user/.config/andromeda/config.toml
  API key        :  0oa7ffaldjci0kge9sjtyz0v40wg
  Port           :  3000
  Binary path    :  /home/user/.local/bin/andromeda-dashboard
  Installed ver  :  v1.5.0
  Audio backend  :  cap  (Linux only — cap | guard | subprocess | pipewire | off)
  Admin mode     :  disabled
  Log file       :  /home/user/.config/andromeda/dashboard.log
```

---

### `config port`

Change the port the dashboard listens on.

```bash
andromeda config port 3001
andromeda config port 8080
```

- If the port is busy, the dashboard automatically tries the next available one
- Takes effect on next `andromeda restart`

---

### `config binary`

Set a custom path to the dashboard binary (useful when building from source).

```bash
andromeda config binary /usr/local/bin/andromeda-dashboard
andromeda config binary ~/dev/andromeda/target/release/andromeda-dashboard
```

---

### `config audio`

Set the audio/camera backend mode. **Linux only** — controls how the dashboard
handles ALSA's `FD_SETSIZE` crash risk.

```bash
andromeda config audio cap
andromeda config audio guard
andromeda config audio subprocess
andromeda config audio pipewire
andromeda config audio off
```

**Modes explained:**

| Mode | FD cap | Behavior | Connections | Requires | Best for |
|------|--------|----------|-------------|---------|----------|
| `cap` | Yes (1024) | Caps `RLIMIT_NOFILE` at startup — ALSA always safe | ~1009 max | Nothing | Desktops / laptops **(default)** |
| `guard` | No | Checks FD count before each audio/camera call; skips if too high | Unlimited | Nothing | Light servers |
| `subprocess` | No | Audio captured in an isolated child process with a fresh FD table | Unlimited | Nothing | High-traffic use *(isolation coming soon)* |
| `pipewire` | No | Routes ALSA through PipeWire bridge — uses epoll, not select() | Unlimited | `pipewire pipewire-alsa wireplumber` | Modern Linux desktops |
| `off` | No | Audio and camera endpoints return 503 — never calls ALSA | Unlimited | Nothing | Headless servers / VMs |

**PipeWire auto-install:** when you set `pipewire` mode on a Debian/Ubuntu system
that doesn't have it yet, Andromeda offers to run:
```
sudo apt-get install -y pipewire pipewire-alsa wireplumber
```

> Takes effect on next `andromeda restart`.

---

## Removal

### `purge`

Delete the dashboard binary only. Keeps your config file, API key, and logs intact.
Useful when you want to re-download a clean binary.

```bash
andromeda purge
andromeda purge -y          # skip confirmation
andromeda purge --yes       # same as -y
```

After purging, run `andromeda install` to re-download.

---

### `uninstall`

Remove all Andromeda data: binary, config, and logs.

```bash
andromeda uninstall
andromeda uninstall -y                    # skip confirmation
andromeda uninstall -y --with-cli         # also delete the andromeda CLI itself
```

| Flag | Short | Description |
|------|-------|-------------|
| `--yes` | `-y` | Skip the "are you sure?" confirmation prompt |
| `--with-cli` | — | Also delete the `andromeda` CLI binary itself |

> **Warning:** `--with-cli` deletes the CLI binary from disk. This cannot be undone
> without re-downloading from GitHub.

---

## Config File Reference

**Location:**

| Platform | Path |
|----------|------|
| Linux / macOS | `~/.config/andromeda/config.toml` |
| Windows | `%APPDATA%\andromeda\config.toml` |

**Full file structure:**

```toml
# Dashboard API key — required to authenticate web UI requests
api_key = "0oa7ffaldjci0kge9sjtyz0v40wg"

# Port the dashboard binds to (tries next port if this one is busy)
port = 3000

# Full path to the dashboard binary
# Defaults to ~/.local/bin/andromeda-dashboard (Linux) / %APPDATA%\andromeda\... (Windows)
binary_path = "/home/user/.local/bin/andromeda-dashboard"

# GitHub repo used by install / update / version commands
dashboard_repo = "Thunder-BluePhoenix/andromeda-releases"

# Version string of the currently installed dashboard binary
installed_version = "v1.5.0"

# Launch the dashboard with elevated/admin mode (ANDROMEDA_SUDO=1)
# Allows the web UI to run system-level commands
sudo = false

# Audio/camera backend (Linux only)
# cap | guard | subprocess | pipewire | off
audio_backend = "cap"
```

All fields are optional — missing fields use sensible defaults.

---

## Quick Reference Card

```
LIFECYCLE
  andromeda self-update          update CLI in-place
  andromeda version              CLI + dashboard version check
  andromeda setup                first-time wizard
  andromeda install              download dashboard binary
  andromeda update               update dashboard to latest

PROCESS
  andromeda start                start (attached to logs)
  andromeda start -d             start in background
  andromeda stop                 stop dashboard
  andromeda restart              stop + start
  andromeda killall              kill ALL dashboard processes
  andromeda status               show status + URLs
  andromeda open                 open in browser

MONITORING
  andromeda logs                 last 50 log lines
  andromeda logs -f              follow live (Ctrl+C to stop)
  andromeda logs -n 100          last 100 lines
  andromeda doctor               health check

API KEY
  andromeda apikey               show current key
  andromeda apikey new           generate new key
  andromeda apikey set <KEY>     set a specific key

INTERNET ACCESS
  andromeda ipv6                 show IPv6 URL
  andromeda tunnel cloudflare    free Cloudflare tunnel
  andromeda tunnel ngrok         ngrok tunnel
  andromeda expose -p 8080       expose local port via IPv6
  andromeda exposed              list exposed ports
  andromeda unexpose -p 8080     stop exposing

CONFIG
  andromeda config show          print all config
  andromeda config port 3001     change port
  andromeda config binary <PATH> set binary path
  andromeda config audio cap     set audio mode

REMOVAL
  andromeda purge                delete binary only
  andromeda uninstall            remove everything
  andromeda uninstall --with-cli remove everything + CLI
```
