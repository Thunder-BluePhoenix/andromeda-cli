# Andromeda CLI

A dedicated command-line manager for [Andromeda Dashboard](https://github.com/Thunder-BluePhoenix/andromeda-releases).

Install the CLI once — then use it to download, start, stop, tunnel, and manage your Andromeda dashboard from any terminal.

---

## Install the CLI

### Windows

```powershell
irm https://raw.githubusercontent.com/Thunder-BluePhoenix/andromeda-cli/main/scripts/install.ps1 | iex
```

Installs `andromeda.exe` to `%LOCALAPPDATA%\Andromeda\` and adds it to your user PATH.

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/Thunder-BluePhoenix/andromeda-cli/main/scripts/install.sh | bash
```

Installs `andromeda` to `/usr/local/bin` (or `~/.local/bin` if no write permission).

---

## Quick Start

```bash
# 1. First-time setup wizard (download binary, set API key, configure internet access)
andromeda setup

# 2. Start the dashboard
andromeda start

# 3. Open a free internet tunnel (no account, no data limits)
andromeda tunnel cloudflare
```

---

## All Commands

| Command | Description |
|---|---|
| `andromeda install` | Download the Andromeda dashboard binary from GitHub releases |
| `andromeda update` | Update the dashboard to the latest release |
| `andromeda setup` | Interactive first-time setup wizard |
| `andromeda start` | Start the dashboard in the background |
| `andromeda start --foreground` | Start the dashboard and stream logs |
| `andromeda stop` | Stop the running dashboard |
| `andromeda restart` | Restart the dashboard |
| `andromeda status` | Show running status and all access URLs |
| `andromeda apikey` | Show the current API key and access URL |
| `andromeda apikey new` | Generate and apply a new random API key |
| `andromeda apikey set <KEY>` | Set a specific API key |
| `andromeda tunnel cloudflare` | Open a free Cloudflare Tunnel (no account needed) |
| `andromeda tunnel ngrok` | Open an ngrok tunnel (requires free account) |
| `andromeda ipv6` | Show IPv6 internet access URL |

---

## How It Works

```
┌─────────────────────────────────────────────┐
│  andromeda-cli  (this repo, PUBLIC)         │
│                                             │
│  andromeda install  ─────────────────────────────► andromeda-releases (PUBLIC)
│                           downloads              (Thunder-BluePhoenix/andromeda-releases)
│                           andromeda-dashboard     andromeda-dashboard-windows-x86_64.exe
│                                                   andromeda-dashboard-linux-x86_64
│  andromeda start    ──► launches binary            andromeda-dashboard-macos-x86_64
│  andromeda stop     ──► kills process              ...
│  andromeda tunnel   ──► cloudflared / ngrok
└─────────────────────────────────────────────┘
         ▲
         │ built by GitHub Actions in
         │ andromeda (PRIVATE source repo)
         └──────────────────────────────────────────
```

### Config & data locations

| Platform | Config file | PID file | Dashboard binary |
|---|---|---|---|
| Windows | `%APPDATA%\andromeda\config.toml` | `%APPDATA%\andromeda\dashboard.pid` | `%LOCALAPPDATA%\Andromeda\andromeda-dashboard.exe` |
| Linux | `~/.config/andromeda/config.toml` | `~/.config/andromeda/dashboard.pid` | `~/.local/share/Andromeda/andromeda-dashboard` |
| macOS | `~/Library/Application Support/andromeda/config.toml` | same dir | `~/Library/Application Support/Andromeda/andromeda-dashboard` |

---

## Internet Access Options

### 1. Cloudflare Tunnel (recommended — free, no account)
```bash
andromeda tunnel cloudflare
```
Opens a free HTTPS tunnel at `https://random.trycloudflare.com`. No data limits, no sign-up required.

### 2. ngrok (requires free account)
```bash
andromeda tunnel ngrok
```
Requires [ngrok](https://ngrok.com) installed and an auth token configured.

### 3. IPv6 (zero-config if available)
```bash
andromeda ipv6
```
If your machine has a global IPv6 address, the dashboard is already accessible from the internet at `http://[your-ipv6]:3000` — no router setup, no tunnel needed.

### 4. Router port forward
Forward TCP port `3000` to your machine's LAN IP in your router's admin panel. `andromeda status` shows your public IP.

---

## Pre-built Binaries

Pre-built CLI binaries are available on the [Releases](https://github.com/Thunder-BluePhoenix/andromeda-cli/releases) page for:

| Platform | File |
|---|---|
| Windows x86_64 | `andromeda-windows-x86_64.exe` |
| Linux x86_64 | `andromeda-linux-x86_64` |
| Linux aarch64 | `andromeda-linux-aarch64` |
| macOS x86_64 | `andromeda-macos-x86_64` |
| macOS Apple Silicon | `andromeda-macos-aarch64` |

---

## Build from Source

```bash
git clone https://github.com/Thunder-BluePhoenix/andromeda-cli
cd andromeda-cli
cargo build --release
# binary at: target/release/andromeda
```

Requires [Rust](https://rustup.rs/) 1.70 or later.

---

## Releasing a New Version

```bash
git tag v0.2.0
git push origin v0.2.0
```

GitHub Actions automatically builds all platform binaries and attaches them to the release.

---

## License

MIT OR Apache-2.0
