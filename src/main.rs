// =============================================================================
// Andromeda CLI
//
// Commands:
//   andromeda version              — CLI version + dashboard version + update check
//   andromeda install              — download dashboard binary from GitHub
//   andromeda update               — smart update (skips if already latest)
//   andromeda start [--detach]     — start dashboard (attaches to logs by default)
//   andromeda stop                 — stop dashboard
//   andromeda killall              — kill all andromeda-dashboard processes on any port
//   andromeda restart              — restart dashboard
//   andromeda status               — show status + URLs
//   andromeda open                 — open dashboard in default browser
//   andromeda logs [-f] [-n N]     — view / follow dashboard logs
//   andromeda doctor               — health check: binary, config, ports, tools
//   andromeda apikey               — show current API key
//   andromeda apikey set <KEY>     — set a specific API key
//   andromeda apikey new           — generate and set a new random key
//   andromeda tunnel cloudflare    — open a free Cloudflare tunnel
//   andromeda tunnel ngrok         — open an ngrok tunnel
//   andromeda ipv6                 — show IPv6 internet access info
//   andromeda config show          — show all config values
//   andromeda config port <PORT>   — set the dashboard port
//   andromeda config binary <PATH> — set the binary path
//   andromeda purge                — delete dashboard binary only (keeps config)
//   andromeda uninstall            — remove dashboard binary and config
//   andromeda setup                — interactive first-time setup wizard
// =============================================================================

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

// ─── CLI Definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "andromeda",
    version,
    about   = "Andromeda Dashboard CLI — install, manage & access your dashboard"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ── Core lifecycle ────────────────────────────────────────────────────────
    /// Check for a new andromeda CLI release and update this binary in-place
    ///
    /// Detects your platform automatically, downloads the correct binary,
    /// and replaces the running CLI without any manual steps.
    SelfUpdate,
    /// Check installed & latest release versions
    Version {
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
    },
    /// First-time setup wizard — permissions, API key, internet access
    Setup {
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
    },
    /// Download the dashboard binary from GitHub releases
    Install {
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
    },
    /// Update the dashboard to the latest GitHub release (skips if already latest)
    Update {
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
    },

    // ── Dashboard process ─────────────────────────────────────────────────────
    /// Start the dashboard  (attached by default — Ctrl+C to stop; use -d to detach)
    Start {
        /// Detach: start in background, print URLs, then exit
        #[arg(long, short = 'd')]
        detach: bool,
    },
    /// Stop the running dashboard
    Stop,
    /// Restart the dashboard
    Restart,
    /// Kill ALL andromeda-dashboard processes regardless of port or PID file
    Killall,
    /// Show dashboard status, PID, and all access URLs
    Status,
    /// Open the dashboard in the default browser
    Open,

    // ── Monitoring ────────────────────────────────────────────────────────────
    /// Follow or show dashboard logs  (-f to stream, -n <lines>)
    Logs {
        /// Stream logs live (like tail -f) — Ctrl+C to stop
        #[arg(long, short = 'f')]
        follow: bool,
        /// Number of recent lines to show (default 50)
        #[arg(long, short = 'n', default_value = "50")]
        lines: usize,
    },
    /// System health check: binary · config · process · port · firewall · tools
    Doctor,

    // ── API key ───────────────────────────────────────────────────────────────
    /// API key management — subcommands: show | new | set <KEY>
    ///
    /// Examples:
    ///   andromeda apikey          — show current key
    ///   andromeda apikey new      — generate a new random key
    ///   andromeda apikey set abc  — set a specific key
    Apikey {
        #[command(subcommand)]
        action: Option<ApikeyAction>,
    },

    // ── Internet access ───────────────────────────────────────────────────────
    /// Show global IPv6 address and direct internet URL (no router config needed)
    Ipv6,
    /// Internet tunnel — subcommands: cloudflare | ngrok
    ///
    /// Examples:
    ///   andromeda tunnel cloudflare  — free tunnel, no account required
    ///   andromeda tunnel ngrok       — instant HTTPS tunnel (ngrok account)
    Tunnel {
        #[command(subcommand)]
        kind: TunnelKind,
    },
    /// Expose a local service to the internet via IPv6 — no router setup needed
    ///
    /// Examples:
    ///   andromeda expose -p 8080                       — expose localhost:8080
    ///   andromeda expose -p 8080 -u 127.0.0.1:8080    — explicit target
    ///   andromeda expose -p 9000 -u 192.168.1.5:3000  — forward to another device
    Expose {
        /// IPv6 port to listen on (what the outside world connects to)
        #[arg(long, short = 'p')]
        port: u16,
        /// Target to proxy to, e.g. 127.0.0.1:8080 — defaults to 127.0.0.1:<port>
        #[arg(long, short = 'u')]
        url: Option<String>,
        /// Human-readable label
        #[arg(long, short = 'n', default_value = "")]
        name: String,
    },
    /// List all currently exposed ports and their IPv6 URLs
    Exposed,
    /// Stop exposing a port  (andromeda unexpose -p <PORT>)
    Unexpose {
        /// Port to stop exposing
        #[arg(long, short = 'p')]
        port: u16,
    },

    // ── Configuration ─────────────────────────────────────────────────────────
    /// Configuration — subcommands: show | port <N> | binary <PATH>
    ///
    /// Examples:
    ///   andromeda config show         — print all config values
    ///   andromeda config port 3001    — change dashboard port
    ///   andromeda config binary /path — set custom binary location
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },

    // ── Removal ───────────────────────────────────────────────────────────────
    /// Delete the dashboard binary only — keeps config, API key, and logs
    Purge {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove all Andromeda data: binary, config, logs  (add --with-cli to also remove this CLI)
    Uninstall {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
        /// Also delete the andromeda CLI binary itself
        #[arg(long)]
        with_cli: bool,
    },
}

#[derive(Subcommand)]
enum ApikeyAction {
    /// Show current API key and access URL
    Show,
    /// Set a specific API key
    Set { key: String },
    /// Generate and apply a new random API key
    New,
}

#[derive(Subcommand)]
enum TunnelKind {
    /// Cloudflare Tunnel — free, no limits, no account required
    Cloudflare,
    /// ngrok tunnel — requires a free ngrok account
    Ngrok,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Show all current config values
    Show,
    /// Set the dashboard port
    Port { port: u16 },
    /// Set the path to the dashboard binary
    Binary { path: String },
    /// Set audio/camera backend (Linux only): cap | guard | subprocess | pipewire | off
    ///
    /// Examples:
    ///   andromeda config audio cap        — cap RLIMIT_NOFILE to 1024 (default, safest)
    ///   andromeda config audio guard      — soft FD check per-call, no hard cap
    ///   andromeda config audio subprocess — audio in isolated subprocess, unlimited FDs
    ///   andromeda config audio pipewire   — PipeWire-ALSA bridge, no FD_SETSIZE limit
    ///   andromeda config audio off        — disable audio and camera entirely
    Audio { mode: String },
}

// ─── Config ───────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Config {
    api_key:           Option<String>,
    port:              Option<u16>,
    binary_path:       Option<String>,
    dashboard_repo:    Option<String>,
    installed_version: Option<String>,
    /// Whether to launch the dashboard with ANDROMEDA_SUDO=1 (admin/elevated mode).
    sudo:              Option<bool>,
    /// Audio/camera backend mode (Linux only).
    ///   cap   — cap RLIMIT_NOFILE to 1024 so ALSA never gets a high FD (default, safest)
    ///   guard — soft FD-count check before each audio call; no hard cap
    ///   off   — disable audio and camera entirely (good for headless/server use)
    audio_backend:     Option<String>,
}

impl Config {
    fn port(&self) -> u16 {
        self.port.unwrap_or(3000)
    }
    fn api_key(&self) -> String {
        self.api_key.clone().unwrap_or_else(|| "not-configured".into())
    }
    fn binary(&self) -> PathBuf {
        self.binary_path.as_deref().map(PathBuf::from).unwrap_or_else(default_binary_path)
    }
    fn sudo_mode(&self) -> bool {
        self.sudo.unwrap_or(false)
    }
    fn audio_backend(&self) -> &str {
        self.audio_backend.as_deref().unwrap_or("cap")
    }
}

fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
        .join("andromeda")
}

fn config_path() -> PathBuf { config_dir().join("config.toml") }
fn pid_path()    -> PathBuf { config_dir().join("dashboard.pid") }
fn log_path()    -> PathBuf { config_dir().join("dashboard.log") }

fn default_binary_path() -> PathBuf {
    let base = dirs::data_local_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")));
    let dir = base.join("Andromeda");
    if cfg!(windows) { dir.join("andromeda-dashboard.exe") }
    else             { dir.join("andromeda-dashboard") }
}

fn load_config() -> Config {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(cfg: &Config) -> Result<()> {
    std::fs::create_dir_all(config_dir()).context("create config dir")?;
    std::fs::write(config_path(), toml::to_string_pretty(cfg)?).context("write config")
}

fn write_pid(pid: u32) -> Result<()> {
    std::fs::create_dir_all(config_dir())?;
    std::fs::write(pid_path(), pid.to_string())?;
    Ok(())
}

fn read_pid() -> Option<u32> {
    std::fs::read_to_string(pid_path()).ok()?.trim().parse().ok()
}

fn clear_pid() { let _ = std::fs::remove_file(pid_path()); }

// ─── Terminal init ────────────────────────────────────────────────────────────

// On Windows, ANSI/VT100 escape codes require ENABLE_VIRTUAL_TERMINAL_PROCESSING
// to be set on the console handle.  Modern Windows Terminal sets this automatically,
// but legacy conhost.exe (classic PowerShell / cmd windows) does not.
#[cfg(target_os = "windows")]
extern "system" {
    fn GetStdHandle(nStdHandle: u32) -> *mut std::ffi::c_void;
    fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
    fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
}

fn init_terminal() {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
            const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

// ─── Output helpers ───────────────────────────────────────────────────────────

fn ok(s: &str)   { println!("\x1b[32m  [+]\x1b[0m {}", s); }
fn warn(s: &str) { println!("\x1b[33m  [!]\x1b[0m {}", s); }
fn err(s: &str)  { println!("\x1b[31m  [x]\x1b[0m {}", s); }
fn info(s: &str) { println!("  {}", s); }
fn dim(s: &str)  { println!("\x1b[90m  {}\x1b[0m", s); }

fn hdr(title: &str) {
    let pad = "─".repeat(54usize.saturating_sub(title.len()));
    println!("\n\x1b[36m  ── {} {}\x1b[0m", title, pad);
}

fn cyan_box(title: &str) {
    println!("\x1b[36m");
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║  {:<56}║", title);
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!("\x1b[0m");
}

fn green_box(title: &str) {
    println!("\x1b[32m");
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║  {:<56}║", title);
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!("\x1b[0m");
}

/// `dashboard_version` — installed dashboard release tag (e.g. "v1.4.0").
/// Falls back to the CLI's own Cargo version if the dashboard is not installed.
fn print_banner(dashboard_version: Option<&str>) {
    let version = dashboard_version.unwrap_or(env!("CARGO_PKG_VERSION"));
    println!("\x1b[36m █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗██████╗  █████╗ \x1b[0m");
    println!("\x1b[36m██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝██╔══██╗██╔══██╗\x1b[0m");
    println!("\x1b[36m███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██╔████╔██║█████╗  ██║  ██║███████║\x1b[0m");
    println!("\x1b[36m██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝  ██║  ██║██╔══██║\x1b[0m");
    println!("\x1b[36m██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗██████╔╝██║  ██║\x1b[0m");
    println!("\x1b[36m╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝\x1b[0m");
    println!("\x1b[90m Remote Dashboard Manager — {}\x1b[0m", version);
    println!();
}

// ─── Key generation ───────────────────────────────────────────────────────────

fn gen_key() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(28)
        .map(char::from)
        .collect::<String>()
        .to_lowercase()
}

// ─── Network ─────────────────────────────────────────────────────────────────

fn local_ip() -> String {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok();
    if let Some(s) = sock {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(a) = s.local_addr() { return a.ip().to_string(); }
        }
    }
    "127.0.0.1".into()
}

fn ipv6_addr() -> Option<String> {
    let s = std::net::UdpSocket::bind("[::]:0").ok()?;
    s.connect("[2001:4860:4860::8888]:80").ok()?;
    let ip = s.local_addr().ok()?.ip().to_string();
    if ip == "::1" || ip.starts_with("fe80") { return None; }
    Some(ip)
}

async fn public_ip() -> Option<String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build().ok()?
        .get("https://api.ipify.org")
        .send().await.ok()?
        .text().await.ok()
        .filter(|s| !s.is_empty())
}

fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(200),
    ).is_ok()
}

// ─── Process management ───────────────────────────────────────────────────────

fn process_alive(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH", "/FO", "CSV"])
            .stdout(Stdio::piped()).stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false)
    }
}

fn kill_pid(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("kill")
            .args([&pid.to_string()])
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false)
    }
}

/// Kill ALL running andromeda-dashboard processes — including orphans that are
/// not tracked by the PID file (e.g. left over from `cargo run`, crashes, or
/// multiple CLI invocations).  Returns the count of PIDs actually killed.
fn kill_all_andromeda() -> u32 {
    let mut killed = 0u32;

    #[cfg(target_os = "windows")]
    {
        // Kill by image name — handles both the installed binary and any dev builds.
        std::process::Command::new("taskkill")
            .args(["/F", "/IM", "andromeda-dashboard.exe"])
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().ok();
        // Count any survivors so the caller knows something happened
        let running = std::process::Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq andromeda-dashboard.exe", "/NH", "/FO", "CSV"])
            .stdout(Stdio::piped()).stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("andromeda-dashboard.exe"))
            .unwrap_or(false);
        if !running { killed = 1; } // taskkill succeeded
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Exclude our own PID so the CLI never kills itself.
        let my_pid = std::process::id();

        // pgrep -f matches against the full command line, catching any port.
        if let Ok(out) = std::process::Command::new("pgrep")
            .args(["-f", "andromeda-dashboard"])
            .output()
        {
            let pids: Vec<u32> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.trim().parse::<u32>().ok())
                .filter(|&p| p != my_pid)
                .collect();

            // Send SIGKILL (-9) — unlike SIGTERM, this cannot be ignored and
            // works on stopped (Ctrl+Z'd) processes too.
            for &pid in &pids {
                let _ = std::process::Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }

            // Give the OS a moment to reap the processes.
            if !pids.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }

            // Count only PIDs that are actually gone now.
            for &pid in &pids {
                let still_alive = std::process::Command::new("kill")
                    .args(["-0", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !still_alive {
                    killed += 1;
                }
            }
        }
    }

    clear_pid();
    killed
}

/// Command: killall — stop every andromeda-dashboard process on the system.
fn cmd_killall() {
    cyan_box("ANDROMEDA — KILL ALL");
    let n = kill_all_andromeda();
    if n > 0 {
        ok(&format!("All andromeda-dashboard processes stopped ({} killed).", n));
    } else {
        info("No running andromeda-dashboard processes found.");
    }
}

// ─── Linux dependency check ───────────────────────────────────────────────────

/// Map a missing shared-library name to the package that provides it,
/// per package manager.
#[cfg(target_os = "linux")]
fn missing_lib_to_packages(lib: &str) -> (&'static str, &'static str, &'static str) {
    // (apt/deb package, dnf/rpm package, pacman package)
    if lib.contains("xdo") {
        ("xdotool", "xdotool", "xdotool")
    } else if lib.contains("asound") {
        ("libasound2", "alsa-lib", "alsa-lib")
    } else if lib.contains("v4l") {
        ("libv4l2-0", "libv4l", "v4l-utils")
    } else if lib.contains("Xtst") {
        ("libxtst6", "libXtst", "libxtst")
    } else if lib.contains("Xfixes") {
        ("libxfixes3", "libXfixes", "libxfixes")
    } else if lib.contains("Xext") {
        ("libxext6", "libXext", "libxext")
    } else if lib.contains("X11") {
        ("libx11-6", "libX11", "libx11")
    } else if lib.contains("xcb") {
        ("libxcb1", "libxcb", "libxcb")
    } else {
        ("", "", "")
    }
}

/// Run `ldd` against the dashboard binary to find missing shared libraries.
/// Prints actionable install instructions and returns `false` if unresolved
/// libs remain so the caller can abort the spawn.
#[cfg(target_os = "linux")]
fn linux_check_deps(binary: &PathBuf) -> bool {
    let out = match std::process::Command::new("ldd")
        .arg(binary)
        .stdout(Stdio::piped()).stderr(Stdio::piped())
        .output()
    {
        Ok(o) => o,
        Err(_) => return true, // ldd not available — optimistically proceed
    };

    let text = String::from_utf8_lossy(&out.stdout);
    let mut missing_apt:    Vec<&'static str> = Vec::new();
    let mut missing_dnf:    Vec<&'static str> = Vec::new();
    let mut missing_pacman: Vec<&'static str> = Vec::new();

    for line in text.lines() {
        if !line.contains("not found") { continue; }
        // ldd lines look like: "  libxdo.so.3 => not found"
        let lib = line.split_whitespace().next().unwrap_or("").trim();
        let (apt, dnf, pac) = missing_lib_to_packages(lib);
        if !apt.is_empty()    && !missing_apt.contains(&apt)       { missing_apt.push(apt); }
        if !dnf.is_empty()    && !missing_dnf.contains(&dnf)       { missing_dnf.push(dnf); }
        if !pac.is_empty()    && !missing_pacman.contains(&pac)     { missing_pacman.push(pac); }

        if apt.is_empty() {
            // Unknown lib — print the raw name so the user knows what's missing
            warn(&format!("Missing library: {} (install manually)", lib));
        }
    }

    if missing_apt.is_empty() && missing_dnf.is_empty() && missing_pacman.is_empty() {
        return true; // all deps satisfied
    }

    err("Dashboard is missing required system libraries:");
    println!();

    // Try to auto-install with whatever package manager is available
    let installed_all = if find_bin("apt-get").is_some() {
        let pkgs: Vec<&str> = missing_apt.iter().map(|s| *s).collect();
        info(&format!("Installing via apt-get: {}", pkgs.join(" ")));
        let success = std::process::Command::new("sudo")
            .args(["apt-get", "install", "-y"])
            .args(&pkgs)
            .status().map(|s| s.success()).unwrap_or(false);
        if success { ok("Dependencies installed."); true }
        else {
            warn("Auto-install failed. Run manually:");
            info(&format!("  sudo apt-get install -y {}", pkgs.join(" ")));
            false
        }
    } else if find_bin("dnf").is_some() {
        let pkgs: Vec<&str> = missing_dnf.iter().map(|s| *s).collect();
        info(&format!("Install missing libs with:"));
        info(&format!("  sudo dnf install -y {}", pkgs.join(" ")));
        false
    } else if find_bin("pacman").is_some() {
        let pkgs: Vec<&str> = missing_pacman.iter().map(|s| *s).collect();
        info("Install missing libs with:");
        info(&format!("  sudo pacman -S {}", pkgs.join(" ")));
        false
    } else {
        info("Install the missing libraries using your distro's package manager.");
        false
    };

    if installed_all {
        println!();
        info("Re-run  andromeda start  to launch the dashboard.");
        // Even though we installed successfully, return false so cmd_start
        // doesn't attempt to spawn immediately — a fresh run ensures clean state.
        false
    } else {
        println!();
        false
    }
}

/// Scan the log from `start_offset` for known fatal error patterns and return
/// a human-readable explanation + fix hint if one is found.
fn scan_log_for_crash_reason(start_offset: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let path = log_path();
    let mut file = std::fs::File::open(&path).ok()?;
    file.seek(SeekFrom::Start(start_offset)).ok()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;

    // Missing shared library (Linux)
    if let Some(pos) = buf.find("error while loading shared libraries:") {
        let snippet = &buf[pos..];
        let line = snippet.lines().next().unwrap_or(snippet);
        // Extract the library name
        let lib = line
            .split(':').nth(1)
            .and_then(|s| s.split(':').next())
            .map(|s| s.trim())
            .unwrap_or("unknown library");
        return Some(format!(
            "Missing system library: {}\n  Fix:  sudo apt-get install xdotool libasound2 libv4l2-0 libxtst6",
            lib
        ));
    }

    // Address already in use
    if buf.contains("AddrInUse") || buf.contains("Address already in use") {
        return Some(
            "Port already in use — run  andromeda killall  then try again.".to_string()
        );
    }

    // Permission denied
    if buf.contains("Permission denied") {
        return Some(
            "Permission denied — try running with  andromeda start  as your normal user (not root).".to_string()
        );
    }

    None
}

#[cfg(target_os = "windows")]
fn do_spawn(cmd: &mut std::process::Command) -> Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS:         u32 = 0x00000008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn().context("spawn dashboard")
}

/// Returns the current size of the log file (used as the "start of this run"
/// offset so log tailing only shows output from the current spawn).
fn current_log_offset() -> u64 {
    std::fs::metadata(log_path()).map(|m| m.len()).unwrap_or(0)
}

/// After spawning the dashboard, scan the log from `start_offset` forward and
/// return the port it actually bound to.  This handles the case where the
/// configured port (e.g. 3000) was already occupied and the dashboard chose
/// the next available one (e.g. 3001).  Times out after 15 s.
async fn detect_actual_port(start_offset: u64, pid: u32) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let path = log_path();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

    loop {
        if tokio::time::Instant::now() > deadline { return None; }
        if !process_alive(pid)                    { return None; }

        if let Ok(mut file) = tokio::fs::File::open(&path).await {
            if file.seek(tokio::io::SeekFrom::Start(start_offset)).await.is_ok() {
                let mut buf = String::new();
                let _ = file.read_to_string(&mut buf).await;
                // Dashboard prints: "  Localhost:  http://localhost:PORT?api_key=..."
                // (with leading spaces — trim before matching)
                for line in buf.lines() {
                    if let Some(rest) = line.trim_start().strip_prefix("Localhost:") {
                        if let Some(port_part) = rest.split("http://localhost:").nth(1) {
                            if let Ok(p) = port_part.split('?').next()
                                .unwrap_or("").trim().parse::<u16>()
                            {
                                return Some(p);
                            }
                        }
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Stream new lines from the log file (starting at `start_offset`) to stdout
/// until the process with `pid` is no longer alive.
/// Using `start_offset` ensures we only show output from this run, not all
/// previous runs stored in the same log file.
async fn follow_log_until_exit(pid: u32, start_offset: u64) {
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
    use std::io::Write;

    let path = log_path();
    // Wait briefly for the log file to be created by the dashboard process.
    for _ in 0..20 {
        if path.exists() { break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return,
    };

    // Skip all output that existed before this run.
    let _ = file.seek(tokio::io::SeekFrom::Start(start_offset)).await;

    let mut reader = BufReader::new(file);
    let mut line   = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF — check whether the process is still alive.
                if !process_alive(pid) { return; }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(_) => {
                print!("{}", line);
                let _ = std::io::stdout().flush();
            }
            Err(_) => return,
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn do_spawn(cmd: &mut std::process::Command) -> Result<std::process::Child> {
    cmd.spawn().context("spawn dashboard")
}

fn spawn_bg(binary: &PathBuf, api_key: &str, port: u16, sudo: bool, audio_backend: &str) -> Result<u32> {
    std::fs::create_dir_all(config_dir())?;

    // Rotate log if > 10 MB to avoid unbounded growth
    let lp = log_path();
    if let Ok(meta) = std::fs::metadata(&lp) {
        if meta.len() > 10 * 1_048_576 {
            let old = config_dir().join("dashboard.log.old");
            let _ = std::fs::rename(&lp, old);
        }
    }

    let log_file = std::fs::OpenOptions::new()
        .create(true).append(true).open(&lp)
        .context("open dashboard log file")?;
    let err_file = log_file.try_clone()?;

    let mut cmd = std::process::Command::new(binary);
    cmd.env("ANDROMEDA_API_KEY", api_key)
       .env("ANDROMEDA_PORT", port.to_string())
       .env("ANDROMEDA_SUDO", if sudo { "1" } else { "0" })
       // Audio/camera backend mode — see `andromeda config audio`.
       .env("ANDROMEDA_AUDIO_BACKEND", audio_backend)
       // Suppress verbose ALSA "unable to open slave" / "Unknown PCM" spam on Linux.
       // These messages come from cpal enumerating audio devices and are harmless
       // but clutter the dashboard log.
       .env("ALSA_DEBUG_LEVEL", "0")
       .stdin(Stdio::null())
       .stdout(Stdio::from(log_file))
       .stderr(Stdio::from(err_file));

    // Run the dashboard from its own directory so relative file paths
    // (static assets, databases, config files) resolve correctly.
    if let Some(dir) = binary.parent() {
        cmd.current_dir(dir);
    }

    Ok(do_spawn(&mut cmd)?.id())
}

// ─── Download utilities ───────────────────────────────────────────────────────

fn dashboard_asset_name() -> String {
    let os = match std::env::consts::OS {
        "windows" => "windows",
        "macos"   => "macos",
        _         => "linux",
    };
    let arch = match std::env::consts::ARCH {
        "x86_64"  => "x86_64",
        "aarch64" => "aarch64",
        "arm"     => "arm",
        _         => "x86_64",
    };
    if cfg!(windows) {
        format!("andromeda-dashboard-{}-{}.exe", os, arch)
    } else {
        format!("andromeda-dashboard-{}-{}", os, arch)
    }
}

/// Asset name for the CLI binary itself (used by self-update).
fn cli_asset_name() -> String {
    let os = match std::env::consts::OS {
        "windows" => "windows",
        "macos"   => "macos",
        _         => "linux",
    };
    let arch = match std::env::consts::ARCH {
        "x86_64"  => "x86_64",
        "aarch64" => "aarch64",
        _         => "x86_64",
    };
    if cfg!(windows) {
        format!("andromeda-{}-{}.exe", os, arch)
    } else {
        format!("andromeda-{}-{}", os, arch)
    }
}

// ─── Command: self-update ─────────────────────────────────────────────────────

async fn cmd_self_update() -> Result<()> {
    use std::io::Write as _;

    cyan_box("ANDROMEDA CLI — SELF UPDATE");

    let current_ver = concat!("v", env!("CARGO_PKG_VERSION"));
    let cli_repo    = "Thunder-BluePhoenix/andromeda-cli";
    let asset_name  = cli_asset_name();

    info(&format!("Current version  :  {}", current_ver));
    print!("  Checking latest release...  ");
    std::io::stdout().flush().ok();

    let (latest_tag, download_url) =
        github_latest_asset(cli_repo, &asset_name).await
            .context("Could not fetch latest CLI release from GitHub")?;

    // Clear the "Checking..." line
    print!("\r{}\r", " ".repeat(50));
    std::io::stdout().flush().ok();

    info(&format!("Latest version   :  {}", latest_tag));

    if latest_tag == current_ver {
        ok("Already up to date — nothing to do.");
        return Ok(());
    }

    println!();
    print!("  Update CLI  {}  →  {}?  [Y/n]: ", current_ver, latest_tag);
    std::io::stdout().flush().ok();
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans).ok();
    if ans.trim().to_lowercase().starts_with('n') {
        info("Update cancelled.");
        return Ok(());
    }
    println!();

    // Locate the running binary
    let current_exe = std::env::current_exe()
        .context("Could not determine current CLI binary path")?
        .canonicalize()
        .context("Could not resolve CLI binary path")?;

    // Temp file lives next to the current binary so rename is on the same filesystem
    let exe_dir  = current_exe.parent().context("CLI binary has no parent directory")?;
    let tmp_path = exe_dir.join(if cfg!(windows) { "andromeda.tmp.exe" } else { "andromeda.tmp" });

    info(&format!("Downloading  {}  →  tmp", asset_name));
    download_to(&download_url, &tmp_path).await?;

    // Make executable on Unix
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
            .context("Could not chmod new binary")?;
    }

    // Remove macOS Gatekeeper quarantine flag
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("xattr")
            .args(["-d", "com.apple.quarantine", &tmp_path.to_string_lossy().into_owned()])
            .output();
    }

    // ── Replace the binary ────────────────────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    {
        // On Unix, rename is atomic and works even while the process is running.
        std::fs::rename(&tmp_path, &current_exe)
            .context("Could not replace CLI binary")?;
        ok(&format!("Updated to {}  —  {}", latest_tag, current_exe.display()));
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows a running binary can be RENAMED but not deleted or overwritten.
        // Strategy: rename old → .bak, rename new → current, delete .bak via detached cmd.
        let bak_path = exe_dir.join("andromeda.bak.exe");
        let _ = std::fs::remove_file(&bak_path); // remove stale bak if any

        std::fs::rename(&current_exe, &bak_path)
            .context("Could not rename current CLI binary (is another process holding it?)")?;
        if let Err(e) = std::fs::rename(&tmp_path, &current_exe) {
            // Roll back: try to restore old binary
            let _ = std::fs::rename(&bak_path, &current_exe);
            return Err(e.into());
        }

        // Delete the .bak file after 2 s via a detached cmd (we can't delete it now)
        let bak_str = bak_path.to_string_lossy().into_owned();
        let script  = format!("ping 127.0.0.1 -n 3 >nul & del /F /Q \"{}\"", bak_str);
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        std::process::Command::new("cmd")
            .args(["/C", &script])
            .creation_flags(DETACHED_PROCESS)
            .spawn().ok();

        ok(&format!("Updated to {}  —  {}", latest_tag, current_exe.display()));
    }

    println!();
    info("Run  andromeda version  to verify the new version.");
    Ok(())
}

async fn github_latest_asset(repo: &str, asset_name: &str) -> Result<(String, String)> {
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let resp: serde_json::Value = reqwest::Client::builder()
        .user_agent("andromeda-cli")
        .timeout(Duration::from_secs(30))
        .build()?
        .get(&api_url).send().await.context("GitHub API request")?
        .json().await.context("parse GitHub API response")?;

    let tag = resp["tag_name"].as_str().unwrap_or("?").to_string();
    for asset in resp["assets"].as_array().context("no assets in release")? {
        if asset["name"].as_str() == Some(asset_name) {
            if let Some(url) = asset["browser_download_url"].as_str() {
                return Ok((tag, url.to_string()));
            }
        }
    }
    bail!("Asset '{}' not found in release {}.\nAvailable: {}",
        asset_name, tag,
        resp["assets"].as_array().map(|a| {
            a.iter().filter_map(|x| x["name"].as_str()).collect::<Vec<_>>().join(", ")
        }).unwrap_or_default()
    )
}

async fn github_latest_tag(repo: &str) -> Result<String> {
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let resp: serde_json::Value = reqwest::Client::builder()
        .user_agent("andromeda-cli")
        .timeout(Duration::from_secs(10))
        .build()?
        .get(&api_url).send().await.context("GitHub API request")?
        .json().await.context("parse response")?;
    Ok(resp["tag_name"].as_str().unwrap_or("?").to_string())
}

async fn download_to(url: &str, dest: &PathBuf) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    if let Some(p) = dest.parent() {
        tokio::fs::create_dir_all(p).await?;
    }
    let resp = reqwest::Client::builder()
        .user_agent("andromeda-cli")
        .timeout(Duration::from_secs(300))
        .build()?
        .get(url).send().await.context("download request")?;

    let total = resp.content_length().unwrap_or(0);
    let mut file = tokio::fs::File::create(dest).await?;
    let mut done: u64 = 0;
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("download stream error")?;
        file.write_all(&chunk).await?;
        done += chunk.len() as u64;
        if total > 0 {
            print!("\r  Downloading... {}%  ({}/{} MB)    ",
                done * 100 / total, done / 1_048_576, total / 1_048_576);
        } else {
            print!("\r  Downloading... {} MB    ", done / 1_048_576);
        }
    }
    println!();
    Ok(())
}

// ─── Cloudflared helpers ──────────────────────────────────────────────────────

fn find_bin(name: &str) -> Option<String> {
    let check = if cfg!(windows) { "where" } else { "which" };
    std::process::Command::new(check).arg(name)
        .stdout(Stdio::piped()).stderr(Stdio::null())
        .output().ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout)
                     .lines().next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
}

#[allow(unreachable_code)]
async fn install_cloudflared() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let ok = std::process::Command::new("winget")
            .args(["install", "--id", "Cloudflare.cloudflared", "-e", "--silent"])
            .status().map(|s| s.success()).unwrap_or(false);
        if ok { return Ok(()); }
        bail!("winget install failed.\nInstall manually: https://github.com/cloudflare/cloudflared/releases");
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("brew")
            .args(["install", "cloudflared"])
            .status().context("brew install cloudflared")?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let arch = match std::env::consts::ARCH {
            "x86_64"  => "amd64",
            "aarch64" => "arm64",
            "arm"     => "arm",
            _         => "amd64",
        };
        let url = format!(
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{}",
            arch
        );
        let dest = PathBuf::from("/usr/local/bin/cloudflared");
        download_to(&url, &dest).await?;
        #[allow(unused_imports)]
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        return Ok(());
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    bail!("Unsupported OS — install cloudflared manually: https://github.com/cloudflare/cloudflared/releases");

    Ok(())
}

fn cf_extract_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let rest = &line[start..];
    if !rest.contains(".trycloudflare.com") { return None; }
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

// ─── Command: version ────────────────────────────────────────────────────────

async fn cmd_version(repo: &str) {
    use std::io::Write;

    cyan_box("ANDROMEDA VERSION");

    let cli_ver = env!("CARGO_PKG_VERSION");
    info(&format!("CLI version      :  v{}", cli_ver));

    let cfg = load_config();

    // Installed dashboard version — from config or by running the binary
    let installed = cfg.installed_version.clone().or_else(|| {
        let binary = cfg.binary();
        if !binary.exists() { return None; }
        std::process::Command::new(&binary)
            .arg("--version")
            .stdout(Stdio::piped()).stderr(Stdio::null())
            .output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    });

    match &installed {
        Some(v) => info(&format!("Dashboard        :  {} (installed)", v)),
        None    => warn("Dashboard        :  not installed — run 'andromeda install'"),
    }

    // Latest release on GitHub
    print!("  Latest release   :  checking...");
    std::io::stdout().flush().ok();

    match github_latest_tag(repo).await {
        Ok(latest) => {
            // Overwrite the "checking..." line with spaces then reprint cleanly.
            print!("\r{}\r", " ".repeat(50));
            info(&format!("Latest release   :  {}", latest));
            if let Some(inst) = &installed {
                if inst == &latest {
                    ok("Dashboard is up to date.");
                } else {
                    warn(&format!("Update available: {} → {}", inst, latest));
                    info("Run 'andromeda update' to upgrade.");
                }
            }
        }
        Err(_) => {
            print!("\r{}\r", " ".repeat(50));
            warn("Latest release   :  could not reach GitHub");
        }
    }
    println!();
}

// ─── Command: install ────────────────────────────────────────────────────────

async fn cmd_install(repo: &str) -> Result<()> {
    cyan_box("ANDROMEDA — INSTALL DASHBOARD");

    let asset = dashboard_asset_name();
    hdr("RELEASE INFO");
    info(&format!("Repository : {}", repo));
    info(&format!("Asset      : {}", asset));

    let (tag, url) = github_latest_asset(repo, &asset).await?;
    ok(&format!("Release    : {}", tag));

    let dest = default_binary_path();

    // Kill any running dashboard before overwriting its binary (Windows file-lock).
    let n = kill_all_andromeda();
    if n > 0 {
        info("Stopped running dashboard for install...");
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }

    hdr("DOWNLOADING");
    info(&format!("→ {}", dest.display()));

    // Retry on Windows in case the process just released the file lock.
    #[cfg(target_os = "windows")]
    {
        let mut attempt = 0u32;
        loop {
            match download_to(&url, &dest).await {
                Ok(()) => break,
                Err(e) if e.to_string().contains("32") && attempt < 5 => {
                    attempt += 1;
                    info(&format!("  File still locked, retrying ({}/5)...", attempt));
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    download_to(&url, &dest).await?;

    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }

    // macOS silently blocks unsigned binaries downloaded from the internet
    // (Gatekeeper quarantine). Remove the attribute so the dashboard can run.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("xattr")
            .args(["-d", "com.apple.quarantine", &dest.to_string_lossy().into_owned()])
            .output();
    }

    let mut cfg = load_config();
    cfg.binary_path        = Some(dest.to_string_lossy().into());
    cfg.dashboard_repo     = Some(repo.into());
    cfg.installed_version  = Some(tag.clone());
    if cfg.api_key.is_none() {
        let k = gen_key();
        ok(&format!("API key    : {}  (saved to config)", k));
        cfg.api_key = Some(k);
    }
    save_config(&cfg)?;

    green_box("ANDROMEDA DASHBOARD INSTALLED");
    println!();
    info("Next:  andromeda setup   — interactive wizard");
    info("  or:  andromeda start   — start immediately");
    Ok(())
}

// ─── Command: update ─────────────────────────────────────────────────────────

async fn cmd_update(repo: &str) -> Result<()> {
    cyan_box("ANDROMEDA — UPDATE DASHBOARD");

    let cfg   = load_config();
    let asset = dashboard_asset_name();

    let (latest_tag, url) = github_latest_asset(repo, &asset).await?;
    let installed = cfg.installed_version.as_deref().unwrap_or("unknown");

    info(&format!("Installed  : {}", installed));
    info(&format!("Latest     : {}", latest_tag));

    if installed == latest_tag {
        ok("Already on the latest version — nothing to do.");
        return Ok(());
    }

    // Kill ALL running instances before overwriting — on Windows a running process
    // locks its binary file and the write would fail with os error 32.
    let was_running = read_pid().map(process_alive).unwrap_or(false);
    {
        let n = kill_all_andromeda();
        if n > 0 || was_running {
            info("Stopped running dashboard(s)...");
            // Give the OS time to release the file lock (especially important on Windows).
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
    }

    let dest = cfg.binary();
    hdr("DOWNLOADING");
    info(&format!("→ {}", dest.display()));

    // On Windows, the old process may still hold a file lock for a moment after
    // being killed.  Retry up to 5 times with a short pause between attempts.
    #[cfg(target_os = "windows")]
    {
        let mut attempt = 0u32;
        loop {
            match download_to(&url, &dest).await {
                Ok(()) => break,
                // os error 32 = ERROR_SHARING_VIOLATION (file still locked)
                Err(e) if e.to_string().contains("32") && attempt < 5 => {
                    attempt += 1;
                    info(&format!("  File still locked, retrying ({}/5)...", attempt));
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    download_to(&url, &dest).await?;

    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }

    // macOS silently blocks unsigned binaries downloaded from the internet
    // (Gatekeeper quarantine). Remove the attribute so the dashboard can run.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("xattr")
            .args(["-d", "com.apple.quarantine", &dest.to_string_lossy().into_owned()])
            .output();
    }

    let mut cfg = load_config();
    cfg.installed_version = Some(latest_tag.clone());
    save_config(&cfg)?;

    ok(&format!("Updated to {}", latest_tag));

    if was_running {
        info("Restarting dashboard...");
        Box::pin(cmd_start(true)).await?;  // detach: update restarts silently
    }
    Ok(())
}

// ─── Command: start ──────────────────────────────────────────────────────────

async fn cmd_start(detach: bool) -> Result<()> {
    let cfg = load_config();
    let binary = cfg.binary();

    if !binary.exists() {
        err("Dashboard binary not found.");
        info("Run first:  andromeda install");
        return Ok(());
    }

    // On Linux, verify all shared-library dependencies are present before
    // spawning.  If any are missing, print install instructions and abort —
    // this avoids the confusing 15-second timeout the user would otherwise see.
    #[cfg(target_os = "linux")]
    if !linux_check_deps(&binary) {
        return Ok(());
    }

    // Already running? Stop it first, then start fresh (auto-restart).
    if let Some(pid) = read_pid() {
        if process_alive(pid) {
            info(&format!("Dashboard already running (PID {}) — stopping first...", pid));
            kill_pid(pid);
            clear_pid();
            tokio::time::sleep(Duration::from_millis(800)).await;
        } else {
            clear_pid();
        }
    }

    let key  = cfg.api_key.clone().unwrap_or_else(gen_key);
    let port = cfg.port();

    // Snapshot the log file size before spawning so we can:
    //  1. Only tail output from THIS run (not historical runs).
    //  2. Scan only the new output to detect the actual port chosen.
    let log_offset = current_log_offset();

    // Always spawn via background helper (stdout/stderr → log file, PID saved).
    // This ensures `andromeda stop` / `andromeda restart` from another terminal
    // always work regardless of whether we attach to the log or not.
    let pid = spawn_bg(&binary, &key, port, cfg.sudo_mode(), cfg.audio_backend())?;
    write_pid(pid)?;
    ok(&format!("Dashboard starting (PID {})...", pid));

    // Wait for the dashboard to print its startup banner (up to 15 s).
    // detect_actual_port reads the log from log_offset and returns the port
    // the dashboard really bound to — which may differ from `port` if that
    // port was already occupied by another process.
    let actual_port = match detect_actual_port(log_offset, pid).await {
        Some(p) => p,
        None => {
            if !process_alive(pid) {
                err("Dashboard exited during startup.");
                if let Some(reason) = scan_log_for_crash_reason(log_offset) {
                    err(&reason);
                } else {
                    info("Run  andromeda logs  to see why.");
                }
                clear_pid();
            } else {
                warn("Dashboard didn't report ready within 15 s — may still be starting.");
                info("Try: andromeda logs -f");
            }
            return Ok(());
        }
    };

    // Small delay then verify the process didn't crash right after printing
    // its banner (e.g. the IPv6 bind-order bug on older macOS binaries).
    tokio::time::sleep(Duration::from_millis(300)).await;
    if !process_alive(pid) {
        err("Dashboard crashed immediately after startup.");
        err("Run `andromeda logs` to see the error:");
        info("  andromeda logs");
        if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
            info(&format!("  To free port {}:  kill $(lsof -ti :{}) 2>/dev/null", actual_port, actual_port));
        }
        clear_pid();
        return Ok(());
    }

    let lan = local_ip();
    let v6  = ipv6_addr();
    let wan = public_ip().await;

    println!();
    green_box("ANDROMEDA IS RUNNING");
    println!();
    println!("  Localhost :  \x1b[37mhttp://localhost:{}?api_key={}\x1b[0m", actual_port, key);
    println!("  LAN       :  \x1b[37mhttp://{}:{}?api_key={}\x1b[0m", lan, actual_port, key);
    if let Some(v6) = &v6 {
        println!("  IPv6      :  \x1b[32mhttp://[{}]:{}?api_key={}\x1b[0m", v6, actual_port, key);
        println!("               ^ internet access — no router setup needed!");
    }
    if let Some(ip) = &wan {
        println!("  Internet  :  http://{}:{}  (forward port {} on your router)", ip, actual_port, actual_port);
    }
    println!();

    // On Linux, warn if UFW is active and the port hasn't been opened.
    // This is the most common reason the dashboard is unreachable from other devices.
    // The dashboard may use any port in the range base..base+9 if base is busy.
    #[cfg(target_os = "linux")]
    {
        let ufw_out = std::process::Command::new("sudo")
            .args(["ufw", "status"])
            .stdout(Stdio::piped()).stderr(Stdio::null())
            .output().ok();
        if let Some(out) = ufw_out {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("Status: active") {
                let base_port = cfg.port();
                let port_str  = actual_port.to_string();
                // A UFW rule may be a single port ("3000/tcp") or a range ("3000:3009/tcp").
                let open = text.lines().any(|l| {
                    if !(l.contains("ALLOW") || l.contains("allow")) { return false; }
                    let rule = l.split_whitespace().next().unwrap_or("").split('/').next().unwrap_or("");
                    if rule.contains(':') {
                        let mut parts = rule.split(':');
                        let lo: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        let hi: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        actual_port >= lo && actual_port <= hi
                    } else {
                        rule == port_str
                    }
                });
                if !open {
                    warn(&format!("UFW firewall: port {} is not open — LAN/internet access blocked.", actual_port));
                    info(&format!("  Fix:  sudo ufw allow {}:{}/tcp", base_port, base_port + 9));
                }
            }
        }
        println!();
    }

    if detach {
        // Detach mode: print hints then exit — dashboard keeps running.
        dim("andromeda stop              — stop the dashboard");
        dim("andromeda open              — open in browser");
        dim("andromeda logs -f           — follow dashboard logs");
        dim("andromeda tunnel cloudflare — open a free internet tunnel");
        return Ok(());
    }

    // ── Attached mode (default) ───────────────────────────────────────────────
    // Stream the dashboard log to this terminal, starting from log_offset so
    // only output from THIS run is shown (not replayed historical output).
    // Ctrl+C here stops the dashboard.
    // `andromeda stop` / `andromeda restart` from another terminal also work.
    dim("─────────────────────────────────────────────────────────────────");
    dim("Attached to dashboard — Ctrl+C to stop.");
    dim("To stop from another terminal: andromeda stop");
    dim("─────────────────────────────────────────────────────────────────");
    println!();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!();
            ok("Stopping dashboard...");
            kill_pid(pid);
            clear_pid();
        }
        _ = follow_log_until_exit(pid, log_offset) => {
            // Dashboard exited on its own (killed from another terminal, etc.).
            clear_pid();
            println!();
            warn("Dashboard stopped.");
        }
    }

    Ok(())
}

// ─── Command: stop ───────────────────────────────────────────────────────────

fn cmd_stop() {
    match read_pid() {
        Some(pid) if process_alive(pid) => {
            if kill_pid(pid) { clear_pid(); ok(&format!("Dashboard stopped (PID {})", pid)); }
            else             { err(&format!("Could not stop PID {}", pid)); }
        }
        Some(pid) => { warn(&format!("Not running (stale PID {})", pid)); clear_pid(); }
        None      => warn("Dashboard is not running."),
    }
}

// ─── Command: status ─────────────────────────────────────────────────────────

async fn cmd_status() {
    let cfg  = load_config();
    let port = cfg.port();
    let key  = cfg.api_key();

    hdr("STATUS");
    match read_pid() {
        Some(pid) if process_alive(pid) => {
            ok(&format!("Running  (PID {})", pid));
            println!();
            println!("  Localhost :  \x1b[37mhttp://localhost:{}?api_key={}\x1b[0m", port, key);
            println!("  LAN       :  \x1b[37mhttp://{}:{}?api_key={}\x1b[0m", local_ip(), port, key);
            if let Some(v6) = ipv6_addr() {
                println!("  IPv6      :  \x1b[32mhttp://[{}]:{}?api_key={}\x1b[0m", v6, port, key);
            }
        }
        Some(pid) => { warn(&format!("Stopped  (stale PID {})", pid)); clear_pid(); }
        None      => warn("Stopped"),
    }
    println!();
    dim(&format!("Binary   :  {}", cfg.binary().display()));
    dim(&format!("Config   :  {}", config_path().display()));
    dim(&format!("Log      :  {}", log_path().display()));
    if let Some(v) = &cfg.installed_version {
        dim(&format!("Version  :  {}", v));
    }
}

// ─── Command: open ───────────────────────────────────────────────────────────

fn cmd_open() {
    let cfg  = load_config();
    let port = cfg.port();
    let key  = cfg.api_key();

    let running = read_pid().map(process_alive).unwrap_or(false) || port_open(port);
    if !running {
        warn("Dashboard is not running.");
        info("Start it first:  andromeda start");
        return;
    }

    let url = format!("http://localhost:{}?api_key={}", port, key);
    info(&format!("Opening: {}", url));

    #[cfg(target_os = "windows")]
    let r = std::process::Command::new("cmd").args(["/C", "start", "", &url]).spawn();

    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(&url).spawn();

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let r = std::process::Command::new("xdg-open").arg(&url).spawn();

    match r {
        Ok(_)  => ok("Opened in default browser."),
        Err(e) => { err(&format!("Could not open browser: {}", e)); info(&format!("Open manually: {}", url)); }
    }
}

// ─── Command: logs ───────────────────────────────────────────────────────────

fn cmd_logs(follow: bool, lines: usize) {
    use std::io::Read;

    let lp = log_path();
    if !lp.exists() {
        warn("No log file found.");
        info(&format!("Expected at: {}", lp.display()));
        info("The log is created when you start the dashboard: andromeda start");
        return;
    }

    // Print last N lines
    let content = match std::fs::read_to_string(&lp) {
        Ok(c)  => c,
        Err(e) => { err(&format!("Read error: {}", e)); return; }
    };
    let all: Vec<&str> = content.lines().collect();
    let start = all.len().saturating_sub(lines);
    for line in &all[start..] { println!("{}", line); }

    if !follow { return; }

    // Follow mode: poll for appended bytes
    let mut file = match std::fs::File::open(&lp) {
        Ok(f)  => f,
        Err(e) => { err(&format!("Cannot open log: {}", e)); return; }
    };
    // Seek to current end
    let _ = std::io::Seek::seek(&mut file, std::io::SeekFrom::End(0));
    dim("Following log — Ctrl+C to stop...");
    loop {
        let mut buf = String::new();
        let _ = file.read_to_string(&mut buf);
        if !buf.is_empty() { print!("{}", buf); }
        std::thread::sleep(Duration::from_millis(250));
    }
}

// ─── Command: doctor ─────────────────────────────────────────────────────────

async fn cmd_doctor() {
    cyan_box("ANDROMEDA DOCTOR — HEALTH CHECK");

    let cfg  = load_config();
    let port = cfg.port();

    // Binary
    let binary = cfg.binary();
    if binary.exists() {
        ok(&format!("Binary           : {}", binary.display()));
    } else {
        err(&format!("Binary           : NOT FOUND — run 'andromeda install'"));
        info(&format!("  Expected       : {}", binary.display()));
    }

    // Config file
    if config_path().exists() {
        ok(&format!("Config file      : {}", config_path().display()));
    } else {
        warn("Config file      : not found (will be created on first install)");
    }

    // API key
    if cfg.api_key.is_some() {
        ok("API key          : configured");
    } else {
        warn("API key          : not set — run 'andromeda apikey new'");
    }

    // Installed version
    match &cfg.installed_version {
        Some(v) => ok(&format!("Installed ver    : {}", v)),
        None    => info("Installed ver    : unknown"),
    }

    // Process + port
    match read_pid() {
        Some(pid) if process_alive(pid) => ok(&format!("Dashboard        : running (PID {})", pid)),
        Some(pid) => { warn(&format!("Dashboard        : stopped (stale PID {})", pid)); clear_pid(); }
        None      => warn("Dashboard        : not running"),
    }
    if port_open(port) {
        ok(&format!("Port {}          : open", port));
    } else {
        warn(&format!("Port {}          : not open", port));
    }

    // Log file
    let lp = log_path();
    if lp.exists() {
        let size = std::fs::metadata(&lp).map(|m| m.len()).unwrap_or(0);
        ok(&format!("Log file         : {} ({} KB)", lp.display(), size / 1024));
    } else {
        info("Log file         : not yet created");
    }

    // Internet
    match public_ip().await {
        Some(ip) => ok(&format!("Internet         : reachable (public IP: {})", ip)),
        None     => warn("Internet         : could not reach api.ipify.org"),
    }

    // IPv6
    match ipv6_addr() {
        Some(v6) => ok(&format!("IPv6             : {} (global — internet accessible)", v6)),
        None     => info("IPv6             : no global address detected"),
    }

    // Optional tools
    match find_bin("cloudflared") {
        Some(p) => ok(&format!("cloudflared      : {}", p)),
        None    => info("cloudflared      : not installed (optional, for free tunnels)"),
    }
    match find_bin("ngrok") {
        Some(p) => ok(&format!("ngrok            : {}", p)),
        None    => info("ngrok            : not installed (optional)"),
    }

    // Linux: UFW firewall check
    // The dashboard tries ports base..base+9 so check if the active port (or its
    // range) is covered by a UFW ALLOW rule.
    #[cfg(target_os = "linux")]
    {
        let ufw_out = std::process::Command::new("sudo")
            .args(["ufw", "status"])
            .stdout(Stdio::piped()).stderr(Stdio::null())
            .output().ok();
        if let Some(out) = ufw_out {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("Status: active") {
                let port_str = port.to_string();
                let open = text.lines().any(|l| {
                    if !(l.contains("ALLOW") || l.contains("allow")) { return false; }
                    let rule = l.split_whitespace().next().unwrap_or("").split('/').next().unwrap_or("");
                    if rule.contains(':') {
                        let mut parts = rule.split(':');
                        let lo: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        let hi: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        port >= lo && port <= hi
                    } else {
                        rule == port_str
                    }
                });
                if open {
                    ok(&format!("UFW              : active, port {}/tcp OPEN", port));
                } else {
                    warn(&format!("UFW              : active, port {} BLOCKED — run: sudo ufw allow {}:{}/tcp", port, port, port + 9));
                }
            } else {
                info("UFW              : inactive (no firewall restrictions)");
            }
        }
    }

    println!();
}

// ─── Command: apikey ─────────────────────────────────────────────────────────

fn cmd_apikey_show() {
    let cfg = load_config();
    hdr("API KEY");
    info(&format!("Key  :  \x1b[37m{}\x1b[0m", cfg.api_key()));
    info(&format!("URL  :  \x1b[36mhttp://localhost:{}?api_key={}\x1b[0m", cfg.port(), cfg.api_key()));
}

fn cmd_apikey_set(key: &str) {
    let mut cfg = load_config();
    cfg.api_key = Some(key.to_string());
    std::env::set_var("ANDROMEDA_API_KEY", key);
    match save_config(&cfg) {
        Ok(_) => {
            ok(&format!("API key saved: {}", key));
            info(&format!("URL  :  http://localhost:{}?api_key={}", cfg.port(), key));
            if let Some(pid) = read_pid() {
                if process_alive(pid) {
                    warn("Dashboard running — run 'andromeda restart' for the new key to apply.");
                }
            }
        }
        Err(e) => err(&format!("Save failed: {}", e)),
    }
}

fn cmd_apikey_new() {
    let key = gen_key();
    ok(&format!("Generated  : {}", key));
    cmd_apikey_set(&key);
}

// ─── Command: config ─────────────────────────────────────────────────────────

fn cmd_config_show() {
    hdr("CONFIGURATION");
    let cfg = load_config();
    println!();
    info(&format!("Config file    :  {}", config_path().display()));
    info(&format!("API key        :  {}", cfg.api_key.as_deref().unwrap_or("(not set)")));
    info(&format!("Port           :  {}", cfg.port()));
    info(&format!("Binary path    :  {}", cfg.binary().display()));
    info(&format!("Installed ver  :  {}", cfg.installed_version.as_deref().unwrap_or("unknown")));
    info(&format!("Audio backend  :  {}  (Linux only — cap | guard | subprocess | pipewire | off)", cfg.audio_backend()));
    info(&format!("Admin mode     :  {}", if cfg.sudo_mode() { "enabled" } else { "disabled" }));
    info(&format!("Log file       :  {}", log_path().display()));
    println!();
}

// ─── Linux package helpers ────────────────────────────────────────────────────

/// Check if PipeWire is installed (pw-cli present in PATH).
#[cfg(target_os = "linux")]
fn pipewire_installed() -> bool {
    std::process::Command::new("which")
        .arg("pw-cli")
        .stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Check if apt-get is available (Debian/Ubuntu systems).
#[cfg(target_os = "linux")]
fn has_apt() -> bool {
    std::process::Command::new("which")
        .arg("apt-get")
        .stdout(Stdio::null()).stderr(Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

/// Offer to install PipeWire packages via apt-get.
/// Returns true if PipeWire is available after the call.
#[cfg(target_os = "linux")]
fn ensure_pipewire() -> bool {
    use std::io::Write;

    if pipewire_installed() {
        ok("PipeWire detected — ready.");
        return true;
    }

    warn("PipeWire not found on this system.");
    // pipewire-jack provides the JACK compatibility layer used by the dashboard's
    // PipeWire-native cpal host (cpal::HostId::Jack → PipeWire via pipewire-jack).
    println!("  Required packages: pipewire  pipewire-alsa  pipewire-jack  wireplumber");
    println!();

    if has_apt() {
        print!("  Install now? (sudo apt-get install -y pipewire pipewire-alsa pipewire-jack wireplumber) [Y/n]: ");
        let _ = std::io::stdout().flush();
        let mut ans = String::new();
        let _ = std::io::stdin().read_line(&mut ans);
        if ans.trim().to_lowercase().starts_with('n') {
            warn("Skipped. Install manually before using pipewire mode.");
            return false;
        }
        let ok_install = std::process::Command::new("sudo")
            .args(["apt-get", "install", "-y", "pipewire", "pipewire-alsa", "pipewire-jack", "wireplumber"])
            .status().map(|s| s.success()).unwrap_or(false);
        if ok_install {
            ok("PipeWire installed successfully.");
            info("Run 'systemctl --user enable --now wireplumber pipewire pipewire-pulse' to start it.");
            return true;
        } else {
            err("Install failed. Run manually:");
            info("  sudo apt-get install -y pipewire pipewire-alsa pipewire-jack wireplumber");
            return false;
        }
    } else {
        warn("apt-get not found — install PipeWire manually for your distro:");
        info("  Fedora / RHEL : sudo dnf install pipewire pipewire-alsa pipewire-jack wireplumber");
        info("  Arch          : sudo pacman -S pipewire pipewire-alsa pipewire-jack wireplumber");
        info("  openSUSE      : sudo zypper install pipewire pipewire-alsa pipewire-jack wireplumber");
        false
    }
}

fn cmd_config_set_audio(mode: &str) {
    const VALID: &[&str] = &["cap", "guard", "subprocess", "pipewire", "off"];

    if !VALID.contains(&mode) {
        err(&format!("Unknown audio mode '{}'. Valid: {}", mode, VALID.join(" | ")));
        println!();
        info("  cap        — cap RLIMIT_NOFILE to 1024, ALSA always safe       (default)");
        info("  guard      — soft FD check per-call, no hard cap");
        info("  subprocess — audio in an isolated subprocess, unlimited FDs    (Linux)");
        info("  pipewire   — PipeWire-ALSA bridge, no FD_SETSIZE limit         (Linux)");
        info("  off        — disable audio and camera entirely");
        return;
    }

    // PipeWire mode: check/install required system packages first.
    #[cfg(target_os = "linux")]
    if mode == "pipewire" && !ensure_pipewire() {
        warn("PipeWire not available — mode not saved. Install PipeWire first.");
        return;
    }

    let mut cfg = load_config();
    cfg.audio_backend = Some(mode.to_string());
    match save_config(&cfg) {
        Ok(_) => {
            ok(&format!("Audio backend set to: {}", mode));
            match mode {
                "cap"        => info("Dashboard will cap RLIMIT_NOFILE to 1024 — ALSA always safe."),
                "guard"      => info("Dashboard will check FD count before each audio call."),
                "subprocess" => info("Audio/camera will run in an isolated subprocess — unlimited connections."),
                "pipewire"   => info("Audio routed through PipeWire-ALSA bridge — no FD_SETSIZE limit."),
                "off"        => info("Audio and camera endpoints will be disabled."),
                _ => {}
            }
            if read_pid().map(process_alive).unwrap_or(false) {
                warn("Dashboard running — run 'andromeda restart' to apply.");
            }
        }
        Err(e) => err(&format!("Save failed: {}", e)),
    }
}

fn cmd_config_set_port(port: u16) {
    let mut cfg = load_config();
    cfg.port = Some(port);
    match save_config(&cfg) {
        Ok(_) => {
            ok(&format!("Port set to {}", port));
            if read_pid().map(process_alive).unwrap_or(false) {
                warn("Dashboard running — run 'andromeda restart' to apply.");
            }
        }
        Err(e) => err(&format!("Save failed: {}", e)),
    }
}

fn cmd_config_set_binary(path: &str) {
    let mut cfg = load_config();
    cfg.binary_path = Some(path.to_string());
    match save_config(&cfg) {
        Ok(_) => ok(&format!("Binary path set to: {}", path)),
        Err(e) => err(&format!("Save failed: {}", e)),
    }
}

// ─── Command: purge ──────────────────────────────────────────────────────────

/// Delete the dashboard binary only — leaves config, API key, and logs intact.
/// Use `andromeda install` afterwards to re-download.
fn cmd_purge(yes: bool) {
    use std::io::Write;

    let cfg    = load_config();
    let binary = cfg.binary();

    if !binary.exists() {
        warn(&format!("Dashboard binary not found at {}", binary.display()));
        info("Nothing to delete.");
        return;
    }

    info(&format!("This will delete:  {}", binary.display()));
    info("Config and API key will be kept.");
    println!();

    if !yes {
        print!("  Continue? [y/N]: ");
        std::io::stdout().flush().ok();
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans).ok();
        if ans.trim().to_lowercase() != "y" {
            info("Cancelled.");
            return;
        }
    }

    // Stop dashboard if running before deleting its binary
    let n = kill_all_andromeda();
    if n > 0 {
        info("Stopped running dashboard...");
        std::thread::sleep(Duration::from_millis(800));
    }

    match std::fs::remove_file(&binary) {
        Ok(_) => {
            // Clear the installed version from config so install is required again
            let mut cfg2 = load_config();
            cfg2.installed_version = None;
            let _ = save_config(&cfg2);
            ok(&format!("Deleted: {}", binary.display()));
            info("Run 'andromeda install' to re-download the dashboard.");
        }
        Err(e) => err(&format!("Could not delete binary: {}", e)),
    }
}

// ─── Command: uninstall ──────────────────────────────────────────────────────

fn cmd_uninstall(yes: bool, with_cli: bool) {
    use std::io::Write;

    cyan_box("ANDROMEDA UNINSTALL");

    let cfg      = load_config();
    let dashboard = cfg.binary();
    let config_d  = config_dir();
    let cli_exe   = std::env::current_exe().ok();

    // ── Show what will be removed ─────────────────────────────────────────────
    info("This will remove:");
    if dashboard.exists() {
        info(&format!("  Dashboard binary  : {}", dashboard.display()));
    }
    if config_d.exists() {
        info(&format!("  Config + logs     : {}", config_d.display()));
    }
    if with_cli {
        if let Some(ref p) = cli_exe {
            info(&format!("  CLI binary        : {}", p.display()));
        }
    }
    println!();

    if !yes {
        print!("  Continue? [y/N]: ");
        std::io::stdout().flush().ok();
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans).ok();
        if ans.trim().to_lowercase() != "y" {
            info("Cancelled.");
            return;
        }
    }

    // ── Kill ALL running dashboard processes ──────────────────────────────────
    let n = kill_all_andromeda();
    if n > 0 {
        info(&format!("Stopped {} running dashboard process(es).", n));
        std::thread::sleep(Duration::from_millis(800));
    }

    // ── Delete dashboard binary ───────────────────────────────────────────────
    if dashboard.exists() {
        match std::fs::remove_file(&dashboard) {
            Ok(_)  => ok(&format!("Removed: {}", dashboard.display())),
            Err(e) => err(&format!("Could not remove dashboard binary: {}", e)),
        }
    }

    // ── Delete dashboard install directory if now empty ───────────────────────
    if let Some(dir) = dashboard.parent() {
        if dir.exists() {
            // Only remove the dir if it's empty (don't nuke unrelated files)
            let _ = std::fs::remove_dir(dir); // silently ignore if not empty
        }
    }

    // ── Delete config directory (config.toml, .pid, .log, .log.old) ──────────
    if config_d.exists() {
        match std::fs::remove_dir_all(&config_d) {
            Ok(_)  => ok(&format!("Removed: {}", config_d.display())),
            Err(e) => err(&format!("Could not remove config directory: {}", e)),
        }
    }

    // ── Optionally delete CLI binary itself ───────────────────────────────────
    if with_cli {
        if let Some(cli_path) = cli_exe {
            #[cfg(not(target_os = "windows"))]
            {
                // On Unix the file can be unlinked while the process still runs.
                match std::fs::remove_file(&cli_path) {
                    Ok(_)  => ok(&format!("Removed CLI: {}", cli_path.display())),
                    Err(e) => err(&format!("Could not remove CLI binary: {}", e)),
                }
            }
            #[cfg(target_os = "windows")]
            {
                // On Windows a running binary cannot be deleted directly.
                // Spawn a detached cmd that waits 2 s then deletes the file.
                let path_str = cli_path.to_string_lossy().into_owned();
                let script = format!(
                    "ping 127.0.0.1 -n 3 >nul & del /F /Q \"{}\"",
                    path_str
                );
                use std::os::windows::process::CommandExt;
                const DETACHED_PROCESS: u32 = 0x00000008;
                std::process::Command::new("cmd")
                    .args(["/C", &script])
                    .creation_flags(DETACHED_PROCESS)
                    .spawn().ok();
                ok(&format!("CLI will be deleted in ~2 s: {}", cli_path.display()));
            }
        }
    }

    println!();
    green_box("UNINSTALL COMPLETE");
    println!();
    if !with_cli {
        info("CLI binary kept. To also remove it, run:");
        info("  andromeda uninstall --with-cli");
        println!();
    }
}

// ─── Command: tunnel cloudflare ──────────────────────────────────────────────

async fn cmd_tunnel_cloudflare() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    cyan_box("ANDROMEDA + CLOUDFLARE TUNNEL");

    let cfg  = load_config();
    let port = cfg.port();

    let running = read_pid().map(process_alive).unwrap_or(false) || port_open(port);
    if !running {
        warn("Dashboard is not running.");
        info("Start it first:  andromeda start");
        info("Then try again:  andromeda tunnel cloudflare");
        return Ok(());
    }

    hdr("CLOUDFLARED");
    let cf = match find_bin("cloudflared") {
        Some(p) => { ok(&format!("Found: {}", p)); p }
        None => {
            warn("cloudflared not found — installing...");
            install_cloudflared().await?;
            find_bin("cloudflared").context("cloudflared install succeeded but binary not in PATH")?
        }
    };

    hdr("OPENING TUNNEL");
    info(&format!("Tunneling http://localhost:{}...", port));

    let mut child = tokio::process::Command::new(&cf)
        .args(["tunnel", "--url", &format!("http://localhost:{}", port), "--no-autoupdate"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    let stderr = child.stderr.take().unwrap();
    let mut lines   = BufReader::new(stderr).lines();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut public_url: Option<String> = None;

    'poll: while tokio::time::Instant::now() < deadline {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        if let Some(u) = cf_extract_url(&l) {
                            public_url = Some(u);
                            break 'poll;
                        }
                    }
                    _ => break 'poll,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    match &public_url {
        Some(url) => {
            let full = format!("{}?api_key={}", url, cfg.api_key());
            println!();
            green_box("CLOUDFLARE TUNNEL ACTIVE");
            println!();
            println!("  Internet  :  \x1b[36m{}\x1b[0m", full);
            println!();
            dim("Free · No data limits · No account · Auto HTTPS");
            println!();
        }
        None => {
            warn("Could not detect tunnel URL within 30 s.");
            info("The tunnel may still be starting — check cloudflared output.");
        }
    }

    info("Press Ctrl+C to close the tunnel.");
    tokio::signal::ctrl_c().await?;
    child.kill().await.ok();
    println!("\n  Tunnel closed.");
    Ok(())
}

// ─── Command: tunnel ngrok ───────────────────────────────────────────────────

async fn cmd_tunnel_ngrok() -> Result<()> {
    cyan_box("ANDROMEDA + NGROK TUNNEL");

    let cfg  = load_config();
    let port = cfg.port();

    let running = read_pid().map(process_alive).unwrap_or(false) || port_open(port);
    if !running {
        warn("Dashboard is not running.");
        info("Start it first:  andromeda start");
        return Ok(());
    }

    hdr("NGROK");
    let ngrok = match find_bin("ngrok") {
        Some(n) => { ok(&format!("Found: {}", n)); n }
        None => {
            err("ngrok not found.");
            info("Download: https://ngrok.com/download");
            info("After install, add your auth token:");
            info("  ngrok config add-authtoken <YOUR_TOKEN>");
            return Ok(());
        }
    };

    hdr("OPENING TUNNEL");
    let mut child = tokio::process::Command::new(&ngrok)
        .args(["http", &port.to_string()])
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn()?;

    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?;
    let mut public_url: Option<String> = None;

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(resp) = client.get("http://127.0.0.1:4040/api/tunnels").send().await {
            if let Ok(j) = resp.json::<serde_json::Value>().await {
                if let Some(tunnels) = j["tunnels"].as_array() {
                    for t in tunnels {
                        if let Some(u) = t["public_url"].as_str() {
                            if u.starts_with("https://") {
                                public_url = Some(u.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
        if public_url.is_some() { break; }
    }

    match &public_url {
        Some(url) => {
            let full = format!("{}?api_key={}", url, cfg.api_key());
            println!();
            green_box("NGROK TUNNEL ACTIVE");
            println!();
            println!("  Internet  :  \x1b[36m{}\x1b[0m", full);
            println!();
        }
        None => {
            warn("Could not get ngrok URL.");
            info("Check manually: http://127.0.0.1:4040");
        }
    }

    info("Press Ctrl+C to close the tunnel.");
    tokio::signal::ctrl_c().await?;
    child.kill().await.ok();
    println!("\n  Tunnel closed.");
    Ok(())
}

// ─── Command: ipv6 ───────────────────────────────────────────────────────────

fn cmd_ipv6() {
    hdr("IPv6 INTERNET ACCESS");
    match ipv6_addr() {
        Some(v6) => {
            let cfg = load_config();
            ok(&format!("Global IPv6 detected: {}", v6));
            println!();
            println!("  Access URL:  \x1b[32mhttp://[{}]:{}?api_key={}\x1b[0m",
                v6, cfg.port(), cfg.api_key());
            println!();
            info("Works from any device on the internet — no router setup needed!");
            info("Share this URL with anyone to give them access.");
        }
        None => {
            warn("No global IPv6 address detected.");
            info("Alternatives for internet access:");
            info("  andromeda tunnel cloudflare  — free, no limits, no account");
            info("  andromeda tunnel ngrok       — instant HTTPS tunnel");
        }
    }
}

// ─── Commands: expose / exposed / unexpose ───────────────────────────────────

/// Build `http://localhost:PORT/api/PATH?api_key=KEY` from the local config.
fn dashboard_api_url(path: &str) -> (String, reqwest::header::HeaderMap) {
    let cfg = load_config();
    let url = format!("http://localhost:{}/api/{}", cfg.port(), path.trim_start_matches('/'));
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "X-API-Key",
        reqwest::header::HeaderValue::from_str(&cfg.api_key()).unwrap(),
    );
    (url, headers)
}

async fn cmd_expose(port: u16, url: Option<String>, name: String) -> Result<()> {
    let label  = if name.is_empty() { format!("port-{}", port) } else { name };
    let target = url.unwrap_or_else(|| format!("127.0.0.1:{}", port));

    let (api_url, headers) = dashboard_api_url("expose");
    let body = serde_json::json!({ "name": label, "port": port, "target": target });

    hdr("EXPOSE VIA IPv6");
    let resp = reqwest::Client::new()
        .post(&api_url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Could not reach dashboard: {}", e))?;

    if !resp.status().is_success() {
        let msg = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("{}", msg));
    }

    let info: serde_json::Value = resp.json().await?;
    ok(&format!("Exposed  [::]:{}  →  {}", port, target));
    ok(&format!("IPv6 URL: \x1b[36m{}\x1b[0m", info["ipv6_url"].as_str().unwrap_or("")));
    info_msg("Anyone on the internet can now reach this service via the URL above.");
    Ok(())
}

async fn cmd_exposed() -> Result<()> {
    let (api_url, headers) = dashboard_api_url("expose");
    let resp = reqwest::Client::new()
        .get(&api_url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Could not reach dashboard: {}", e))?;

    let list: Vec<serde_json::Value> = resp.json().await?;
    hdr("ACTIVE IPv6 EXPOSURES");
    if list.is_empty() {
        info_msg("No ports currently exposed.");
        info_msg("Use:  andromeda expose -p <PORT> [-u <TARGET>]");
        return Ok(());
    }

    // Header row
    dim("  PORT           TARGET                    IPv6 ACCESS URL");
    dim("  ─────────────  ────────────────────────  ────────────────────────────────────────");

    for e in &list {
        let port   = e["port"].as_u64().unwrap_or(0);
        let target = e["target"].as_str().unwrap_or("?");
        let ipv6   = e["ipv6_url"].as_str().unwrap_or("?");
        let name   = e["name"].as_str().unwrap_or("");
        let port_s = format!("[::]{}", format!(":{}", port));
        let label  = if name.is_empty() { String::new() }
                     else { format!("  \x1b[90m({})\x1b[0m", name) };
        println!("  \x1b[96m{:<13}\x1b[0m  \x1b[37m{:<24}\x1b[0m  \x1b[36m{}\x1b[0m{}",
            port_s, target, ipv6, label);
    }
    println!();
    info_msg("To stop:  andromeda unexpose -p <PORT>");
    Ok(())
}

async fn cmd_unexpose(port: u16) -> Result<()> {
    let (api_url, headers) = dashboard_api_url(&format!("expose/{}", port));
    let resp = reqwest::Client::new()
        .delete(&api_url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Could not reach dashboard: {}", e))?;

    if resp.status() == 404 {
        return Err(anyhow::anyhow!("Port {} is not currently exposed.", port));
    }
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("HTTP {}", resp.status()));
    }
    ok(&format!("Port {} is no longer exposed.", port));
    Ok(())
}

// small alias so the functions above can use info_msg without clashing with
// the `info` helper that already exists in this file
fn info_msg(s: &str) { info(s); }

// ─── Command: setup ──────────────────────────────────────────────────────────

fn setup_permissions(cfg: &mut Config) -> Result<()> {
    use std::io::Write;

    // ── macOS: TCC permissions ────────────────────────────────────────────────
    #[cfg(target_os = "macos")]
    {
        info("The dashboard uses these macOS permissions:");
        println!("    Screen Recording  — remote screen view");
        println!("    Accessibility     — remote mouse & keyboard control");
        println!("    Camera            — webcam streaming");
        println!("    Microphone        — audio streaming");
        println!();
        info("macOS will ask you to grant each permission the first time the");
        info("feature is used. You can also grant them now via System Settings.");
        println!();
        print!("  Open System Settings › Privacy & Security now? [y/N]: ");
        std::io::stdout().flush()?;
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;
        if ans.trim().to_lowercase() == "y" {
            // Open each relevant pane in System Settings
            for pane in &[
                "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_Camera",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone",
            ] {
                let _ = std::process::Command::new("open").arg(pane).status();
                // Brief pause so each pane has time to open
                std::thread::sleep(std::time::Duration::from_millis(600));
            }
            ok("System Settings opened — grant access to 'andromeda-dashboard' in each pane.");
            info("Press Enter when done...");
            let mut _buf = String::new();
            std::io::stdin().read_line(&mut _buf)?;
        } else {
            info("You can grant permissions later in:");
            info("  System Settings › Privacy & Security › Screen Recording / Accessibility / Camera / Microphone");
        }
        println!();
    }

    // ── Linux: group membership ───────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        let user = std::env::var("USER").unwrap_or_else(|_| "your-user".into());
        let mut needs_logout = false;

        // Check video group (for camera / webcam)
        let in_video = std::process::Command::new("id")
            .arg("-Gn").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("video"))
            .unwrap_or(false);

        if in_video {
            ok("User is in 'video' group  (camera OK)");
        } else {
            warn("User is not in 'video' group  (camera may not work)");
            info(&format!("  Fix:  sudo usermod -aG video {}", user));
            needs_logout = true;
        }

        // Check audio group (for microphone / audio)
        let in_audio = std::process::Command::new("id")
            .arg("-Gn").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("audio"))
            .unwrap_or(false);

        if in_audio {
            ok("User is in 'audio' group  (microphone OK)");
        } else {
            warn("User is not in 'audio' group  (microphone may not work)");
            info(&format!("  Fix:  sudo usermod -aG audio {}", user));
            needs_logout = true;
        }

        if needs_logout {
            println!();
            print!("  Apply group changes now (requires sudo)? [y/N]: ");
            std::io::stdout().flush()?;
            let mut ans = String::new();
            std::io::stdin().read_line(&mut ans)?;
            if ans.trim().to_lowercase() == "y" {
                if !in_video {
                    let status = std::process::Command::new("sudo")
                        .args(["usermod", "-aG", "video", &user]).status();
                    match status {
                        Ok(s) if s.success() => ok("Added to 'video' group"),
                        _ => warn("Could not add to 'video' — run manually with sudo"),
                    }
                }
                if !in_audio {
                    let status = std::process::Command::new("sudo")
                        .args(["usermod", "-aG", "audio", &user]).status();
                    match status {
                        Ok(s) if s.success() => ok("Added to 'audio' group"),
                        _ => warn("Could not add to 'audio' — run manually with sudo"),
                    }
                }
                warn("Log out and back in (or run 'newgrp video && newgrp audio') for group changes to take effect.");
            }
        }

        // Check for missing shared libraries (e.g. libxdo.so.3 from enigo).
        // Do this after group changes so the binary is already in its final state.
        let binary = cfg.binary();
        if binary.exists() {
            hdr("SYSTEM LIBRARIES");
            if linux_check_deps(&binary) {
                ok("All required system libraries are present.");
            }
            // linux_check_deps already prints instructions if anything is missing.
        }

        // Check UFW firewall — Ubuntu blocks all incoming ports by default.
        // The dashboard may use any port in base..base+9 (auto-selects next free port),
        // so we open the whole range to avoid re-running setup if the base port is busy.
        {
            use std::io::Write;
            let port = cfg.port();
            let ufw_status = std::process::Command::new("sudo")
                .args(["ufw", "status"])
                .stdout(Stdio::piped()).stderr(Stdio::null())
                .output();
            if let Ok(out) = ufw_status {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("Status: active") {
                    hdr("FIREWALL (UFW)");
                    let port_str  = port.to_string();
                    let range_str = format!("{}:{}/tcp", port, port + 9);
                    // A UFW rule may be a single port or a range — handle both.
                    let already_open = text.lines().any(|l| {
                        if !(l.contains("ALLOW") || l.contains("allow")) { return false; }
                        let rule = l.split_whitespace().next().unwrap_or("").split('/').next().unwrap_or("");
                        if rule.contains(':') {
                            let mut parts = rule.split(':');
                            let lo: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                            let hi: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                            port >= lo && port <= hi
                        } else {
                            rule == port_str
                        }
                    });
                    if already_open {
                        ok(&format!("UFW: ports {}:{}/tcp are already open.", port, port + 9));
                    } else {
                        warn(&format!("UFW is active — ports {}:{} are NOT open.", port, port + 9));
                        info("The dashboard will bind fine but other devices cannot reach it.");
                        print!("  Open ports {}:{}/tcp in UFW now? [Y/n]: ", port, port + 9);
                        std::io::stdout().flush().ok();
                        let mut ans = String::new();
                        std::io::stdin().read_line(&mut ans).ok();
                        if !ans.trim().to_lowercase().starts_with('n') {
                            let ok2 = std::process::Command::new("sudo")
                                .args(["ufw", "allow", &range_str])
                                .status().map(|s| s.success()).unwrap_or(false);
                            if ok2 {
                                ok(&format!("Ports {}:{}/tcp opened in UFW.", port, port + 9));
                            } else {
                                warn("UFW rule failed — run manually:");
                                info(&format!("  sudo ufw allow {}", range_str));
                            }
                        }
                    }
                }
                // If UFW is inactive or not installed, no action needed.
            }
        }
        println!();
    }

    // ── Windows: administrator check ──────────────────────────────────────────
    #[cfg(target_os = "windows")]
    {
        let is_admin = std::process::Command::new("net")
            .args(["session"]).output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if is_admin {
            ok("Running as Administrator  (all features available)");
        } else {
            warn("Not running as Administrator.");
            info("Some features (firewall rules, system commands) need admin rights.");
            info("To run with admin rights: right-click the terminal → 'Run as administrator'");
            info("Then re-run: andromeda setup");
        }
        println!();
    }

    // ── All platforms: admin/sudo mode ────────────────────────────────────────
    let current = cfg.sudo_mode();
    println!("  Admin mode lets the dashboard run system-level commands from the");
    println!("  web UI (file operations outside home, process management, etc.).");
    println!();
    if current {
        ok("Admin mode is currently ENABLED.");
        print!("  Disable admin mode? [y/N]: ");
    } else {
        info("Admin mode is currently disabled.");
        print!("  Enable admin mode? [y/N]: ");
    }
    std::io::stdout().flush()?;
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    if ans.trim().to_lowercase() == "y" {
        cfg.sudo = Some(!current);
        if !current {
            ok("Admin mode ENABLED  (ANDROMEDA_SUDO=1 will be set on start)");

            // macOS: warn that accessibility must be granted for full admin control
            #[cfg(target_os = "macos")]
            warn("Remember to grant Accessibility permission in System Settings so remote control works.");

            // Linux: remind about sudo
            #[cfg(target_os = "linux")]
            info("The dashboard process inherits your sudo rights — no password prompt in the UI.");

            // Windows: remind about UAC
            #[cfg(target_os = "windows")]
            info("For full admin features, run the terminal as Administrator before `andromeda start`.");
        } else {
            ok("Admin mode DISABLED.");
        }
    } else {
        info("Admin mode unchanged.");
    }

    Ok(())
}

async fn cmd_setup(repo: &str) -> Result<()> {
    use std::io::Write;

    cyan_box("ANDROMEDA SETUP WIZARD");
    let mut cfg = load_config();

    // ── Step 1: Binary ───────────────────────────────────────────────────────
    hdr("STEP 1 — DASHBOARD BINARY");
    let binary = cfg.binary();
    if binary.exists() {
        ok(&format!("Binary found: {}", binary.display()));
    } else {
        warn("Dashboard binary not found.");
        print!("  Download from GitHub now? [Y/n]: ");
        std::io::stdout().flush()?;
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;
        if !ans.trim().to_lowercase().starts_with('n') {
            cmd_install(repo).await?;
            cfg = load_config();
        } else {
            warn("Skipped. Run 'andromeda install' when ready.");
        }
    }

    // ── Step 2: API key ──────────────────────────────────────────────────────
    hdr("STEP 2 — API KEY");
    if let Some(k) = &cfg.api_key {
        ok(&format!("Current key: {}", k));
        print!("  Generate a new key? [y/N]: ");
        std::io::stdout().flush()?;
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;
        if ans.trim().to_lowercase() == "y" {
            cfg.api_key = Some(gen_key());
            ok(&format!("New key: {}", cfg.api_key.as_ref().unwrap()));
        }
    } else {
        cfg.api_key = Some(gen_key());
        ok(&format!("Generated key: {}", cfg.api_key.as_ref().unwrap()));
    }
    save_config(&cfg)?;

    // ── Step 3: Internet access ──────────────────────────────────────────────
    hdr("STEP 3 — INTERNET ACCESS");
    println!("  How do you want internet access?");
    println!("  1) Cloudflare Tunnel — free, no limits, no account  (recommended)");
    if ipv6_addr().is_some() {
        println!("  2) IPv6 — you have a global IPv6 address, works right now!");
    } else {
        println!("  2) IPv6 — not detected on this machine");
    }
    println!("  3) Router port forward — manual config");
    println!("  4) Skip for now");
    print!("  > ");
    std::io::stdout().flush()?;
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    match ans.trim() {
        "1" => { ok("Run 'andromeda tunnel cloudflare' anytime to open a free tunnel."); }
        "2" => cmd_ipv6(),
        "3" => {
            let wan = public_ip().await;
            if let Some(ip) = wan {
                info(&format!("Public IP : {}", ip));
                info(&format!("Forward TCP port {} → {} in your router.", cfg.port(), local_ip()));
            } else {
                warn("Could not detect public IP — check your internet connection.");
            }
        }
        _ => {}
    }

    // ── Step 4: Audio backend (Linux only) ───────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        hdr("STEP 4 — AUDIO / CAMERA BACKEND");
        println!("  ALSA can crash the dashboard when too many connections are open");
        println!("  (FD numbers exceed the select() hard limit of 1024).");
        println!("  Choose how to handle this:");
        println!();

        // Detect what is already available on this system.
        let pw_ok = pipewire_installed();
        let pw_tag = if pw_ok { " [installed]" } else { " [not installed — can install now]" };

        println!("  1) cap        — Safest. Cap RLIMIT_NOFILE to 1024 so ALSA never");
        println!("                  gets a high FD. Up to ~1009 concurrent connections.");
        println!("                  Recommended for most desktop/laptop setups.  [default]");
        println!();
        println!("  2) subprocess — Audio captured in an isolated child process.");
        println!("                  Main dashboard has unlimited FDs and can't crash.");
        println!("                  No extra packages needed.");
        println!();
        println!("  3) pipewire   — Route ALSA through the PipeWire bridge.{}", pw_tag);
        println!("                  PipeWire uses epoll, not select() — no FD_SETSIZE limit.");
        println!("                  Unlimited connections, full audio quality.");
        println!();
        println!("  4) guard      — Soft check per audio/camera call. Skips audio when");
        println!("                  FDs are high. No connection limit but may skip audio.");
        println!();
        println!("  5) off        — Disable audio and camera entirely.");
        println!("                  Best for headless servers with no microphone/webcam.");
        println!();
        print!("  Choice [1]: ");
        std::io::stdout().flush()?;
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;

        let audio_mode: &str = match ans.trim() {
            "2" => "subprocess",
            "3" => {
                // PipeWire: install packages if not present.
                if !pw_ok {
                    ensure_pipewire();
                }
                "pipewire"
            }
            "4" => "guard",
            "5" => "off",
            _   => "cap",
        };
        cfg.audio_backend = Some(audio_mode.to_string());
        save_config(&cfg)?;
        ok(&format!("Audio backend set to: {}", audio_mode));
    }

    // ── Step 5: Permissions ──────────────────────────────────────────────────
    hdr("STEP 5 — PERMISSIONS");
    setup_permissions(&mut cfg)?;
    save_config(&cfg)?;

    // ── Step 6: Start now? ───────────────────────────────────────────────────
    hdr("STEP 6 — START");
    print!("  Start the dashboard now? [Y/n]: ");
    std::io::stdout().flush()?;
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    if !ans.trim().to_lowercase().starts_with('n') {
        Box::pin(cmd_start(false)).await?;
        return Ok(());
    }

    // ── Summary ──────────────────────────────────────────────────────────────
    let port = cfg.port();
    let key  = cfg.api_key();
    let lan  = local_ip();

    println!();
    green_box("SETUP COMPLETE");
    println!();
    println!("  Localhost :  \x1b[37mhttp://localhost:{}?api_key={}\x1b[0m", port, key);
    println!("  LAN       :  \x1b[37mhttp://{}:{}?api_key={}\x1b[0m", lan, port, key);
    if let Some(v6) = ipv6_addr() {
        println!("  IPv6      :  \x1b[32mhttp://[{}]:{}?api_key={}\x1b[0m", v6, port, key);
    }
    println!();
    println!("  Quick reference:");
    dim("  andromeda start                — start dashboard");
    dim("  andromeda stop                 — stop dashboard");
    dim("  andromeda restart              — restart dashboard");
    dim("  andromeda status               — show status + URLs");
    dim("  andromeda open                 — open in browser");
    dim("  andromeda logs -f              — follow dashboard logs");
    dim("  andromeda doctor               — health check");
    dim("  andromeda tunnel cloudflare    — open free internet tunnel");
    dim("  andromeda tunnel ngrok         — open ngrok tunnel");
    dim("  andromeda apikey               — show API key");
    dim("  andromeda apikey new           — rotate API key");
    dim("  andromeda version              — version + update check");
    dim("  andromeda config show          — show all config");
    println!();
    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    init_terminal();
    let cli = Cli::parse();

    // Show the ASCII banner only for version checks and first-time install.
    // Every other command is silent at the start so output stays clean.
    let show_banner = matches!(
        &cli.command,
        Commands::Version { .. } | Commands::Install { .. }
    );
    if show_banner {
        // Use the installed dashboard release tag (e.g. "v1.4.0") as the version
        // shown in the banner.  Falls back to CLI's own Cargo version if not installed.
        let cfg = load_config();
        print_banner(cfg.installed_version.as_deref());
    }

    let result: Result<()> = match cli.command {
        Commands::Version { repo }         => { cmd_version(&repo).await; Ok(()) }
        Commands::Install { repo }         => cmd_install(&repo).await,
        Commands::Update  { repo }         => cmd_update(&repo).await,
        Commands::Start   { detach }       => cmd_start(detach).await,
        Commands::Stop                     => { cmd_stop(); Ok(()) }
        Commands::Killall                  => { cmd_killall(); Ok(()) }
        Commands::Restart                  => {
            cmd_stop();
            tokio::time::sleep(Duration::from_millis(800)).await;
            cmd_start(true).await  // detach: restart silently, don't re-attach
        }
        Commands::Status                   => { cmd_status().await; Ok(()) }
        Commands::Open                     => { cmd_open(); Ok(()) }
        Commands::Logs { follow, lines }   => { cmd_logs(follow, lines); Ok(()) }
        Commands::Doctor                   => { cmd_doctor().await; Ok(()) }
        Commands::Apikey  { action }       => match action.unwrap_or(ApikeyAction::Show) {
            ApikeyAction::Show        => { cmd_apikey_show(); Ok(()) }
            ApikeyAction::Set { key } => { cmd_apikey_set(&key); Ok(()) }
            ApikeyAction::New         => { cmd_apikey_new(); Ok(()) }
        },
        Commands::Tunnel { kind }          => match kind {
            TunnelKind::Cloudflare => cmd_tunnel_cloudflare().await,
            TunnelKind::Ngrok      => cmd_tunnel_ngrok().await,
        },
        Commands::Ipv6                     => { cmd_ipv6(); Ok(()) }
        Commands::Config  { action }       => match action {
            ConfigCmd::Show             => { cmd_config_show(); Ok(()) }
            ConfigCmd::Port { port }    => { cmd_config_set_port(port); Ok(()) }
            ConfigCmd::Binary { path }  => { cmd_config_set_binary(&path); Ok(()) }
            ConfigCmd::Audio { mode }   => { cmd_config_set_audio(&mode); Ok(()) }
        },
        Commands::Purge     { yes }        => { cmd_purge(yes); Ok(()) }
        Commands::Uninstall { yes, with_cli } => { cmd_uninstall(yes, with_cli); Ok(()) }
        Commands::SelfUpdate               => cmd_self_update().await,
        Commands::Setup { repo }           => cmd_setup(&repo).await,
        Commands::Expose { port, url, name } => cmd_expose(port, url, name).await,
        Commands::Exposed                  => cmd_exposed().await,
        Commands::Unexpose { port }        => cmd_unexpose(port).await,
    };

    if let Err(e) = result {
        err(&format!("{:#}", e));
        std::process::exit(1);
    }
}
