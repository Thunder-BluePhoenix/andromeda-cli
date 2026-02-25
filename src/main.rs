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
    /// Show CLI version, installed dashboard version, and latest available
    Version {
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
    },
    /// Download the Andromeda dashboard binary from GitHub releases
    Install {
        /// GitHub repository (owner/repo)
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
    },
    /// Update the dashboard to the latest GitHub release (skips if already latest)
    Update {
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
    },
    /// Start the Andromeda dashboard (follows logs; Ctrl+C stops it)
    Start {
        /// Detach — start in background without following logs
        #[arg(long, short = 'd')]
        detach: bool,
    },
    /// Stop the running Andromeda dashboard
    Stop,
    /// Kill ALL running Andromeda dashboard processes on any port
    Killall,
    /// Restart the Andromeda dashboard
    Restart,
    /// Show dashboard status and access URLs
    Status,
    /// Open the dashboard in the default web browser
    Open,
    /// View or follow dashboard logs
    Logs {
        /// Follow log output (like tail -f)
        #[arg(long, short = 'f')]
        follow: bool,
        /// Number of lines to show
        #[arg(long, short = 'n', default_value = "50")]
        lines: usize,
    },
    /// Check system health: binary, config, process, ports, and tools
    Doctor,
    /// API key management (default: show current key)
    Apikey {
        #[command(subcommand)]
        action: Option<ApikeyAction>,
    },
    /// Internet tunnel management
    Tunnel {
        #[command(subcommand)]
        kind: TunnelKind,
    },
    /// Show IPv6 internet access info
    Ipv6,
    /// Show or modify CLI configuration
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Delete the dashboard binary file only (keeps config and API key)
    Purge {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Remove dashboard binary, config, logs, and all Andromeda data
    Uninstall {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
        /// Also remove the andromeda CLI binary itself
        #[arg(long)]
        with_cli: bool,
    },
    /// Interactive first-time setup wizard
    Setup {
        #[arg(long, default_value = "Thunder-BluePhoenix/andromeda-releases")]
        repo: String,
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
/// multiple CLI invocations).  Returns the count of PIDs targeted.
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
        // pgrep -f matches against the full command line, catching any port.
        if let Ok(out) = std::process::Command::new("pgrep")
            .args(["-f", "andromeda-dashboard"])
            .output()
        {
            let pids: Vec<u32> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();
            killed = pids.len() as u32;
            for pid in pids {
                kill_pid(pid);
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

fn spawn_bg(binary: &PathBuf, api_key: &str, port: u16, sudo: bool) -> Result<u32> {
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
            print!("\r");
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
            print!("\r");
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
    let pid = spawn_bg(&binary, &key, port, cfg.sudo_mode())?;
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
                err("Run `andromeda logs` to see why:");
                info("  andromeda logs");
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
    info(&format!("Log file       :  {}", log_path().display()));
    println!();
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

    // ── Step 4: Permissions ──────────────────────────────────────────────────
    hdr("STEP 4 — PERMISSIONS");
    setup_permissions(&mut cfg)?;
    save_config(&cfg)?;

    // ── Step 5: Start now? ───────────────────────────────────────────────────
    hdr("STEP 5 — START");
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
            ConfigCmd::Show         => { cmd_config_show(); Ok(()) }
            ConfigCmd::Port { port }    => { cmd_config_set_port(port); Ok(()) }
            ConfigCmd::Binary { path }  => { cmd_config_set_binary(&path); Ok(()) }
        },
        Commands::Purge     { yes }        => { cmd_purge(yes); Ok(()) }
        Commands::Uninstall { yes, with_cli } => { cmd_uninstall(yes, with_cli); Ok(()) }
        Commands::Setup { repo }           => cmd_setup(&repo).await,
    };

    if let Err(e) = result {
        err(&format!("{:#}", e));
        std::process::exit(1);
    }
}
