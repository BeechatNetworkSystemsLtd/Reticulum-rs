//! `rn` — multi-call binary for the Reticulum `rn*` utilities
//! (see `reticulum-utils/src/lib.rs`).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use reticulum_utils::common::parse_hash;
use reticulum_utils::rncp::{FetchOptions, SendOptions, ServeOptions};
use reticulum_utils::rnid::IdOptions;

/// Reticulum utility programs (rnid, rnpath, rnstatus, rncp).
#[derive(Parser)]
#[command(name = "rn", version, about = "Reticulum utility programs", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate and inspect Reticulum identities (rnid)
    Id(IdArgs),
    /// Look up paths to destinations (rnpath)
    Path(PathArgs),
    /// Show local instance status (rnstatus)
    Status(StatusArgs),
    /// Transfer files over Reticulum resources (rncp)
    Cp(CpArgs),
    /// Probe transport instances (rnprobe)
    Probe(ProbeArgs),
    /// Remote command execution (rnx)
    X(XArgs),
    /// Remote shell sessions (rnsh)
    Sh(ShArgs),
    /// Reticulum git repositories (rngit) — args passed through to the
    /// rngit dispatcher: node, create, release, perms, work, fork, sync,
    /// mirror
    Git {
        /// rngit arguments (e.g. `create rns://<hash>/<group>/<repo>`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Git commit signer for `gpg.ssh.program` (rngit commitsigs)
    GitSign {
        /// commitsigs arguments (e.g. `-Y sign -f <keyfile> <file>`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// RNode diagnostics and validation (rnodeconf)
    Nodeconf(NodeconfArgs),
    /// RNode device emulator for interface testing
    #[cfg(feature = "iface-rnode")]
    NodeSim(reticulum_utils::rnode_sim::Args),
    /// Identity resolver stub (rnir)
    Ir(CommonArgs),
    /// Package manager stub (rnpkg)
    Pkg(CommonArgs),
}

#[derive(Args)]
struct IdArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Generate a new identity and save it to this path
    #[arg(short, long)]
    generate: Option<PathBuf>,
    /// Hexadecimal Reticulum identity or destination hash, or path to an identity file
    #[arg(short, long)]
    identity: Option<String>,
    /// Only show public key material when no other rnid operation is selected
    #[arg(long)]
    public: bool,
    /// Import a public identity (hex, base32, base64, base256, or file)
    #[arg(short = 'm', long = "import-pub")]
    import_pub: Option<String>,
    /// Import a private identity (hex, base32, base64, base256, or file)
    #[arg(short = 'M', long = "import-prv")]
    import_prv: Option<String>,
    /// Export the public identity
    #[arg(short = 'x', long = "export-pub")]
    export_pub: bool,
    /// Export the private identity
    #[arg(short = 'X', long = "export-prv")]
    export_prv: bool,
    /// Increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Decrease verbosity
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,
    /// Announce a destination based on this identity
    #[arg(
        short = 'a',
        long,
        num_args = 0..=1,
        default_missing_value = "rns.id"
    )]
    announce: Option<String>,
    /// Show destination hashes for aspects of this identity
    #[arg(short = 'H', long)]
    hash: Option<String>,
    /// Decrypt files
    #[arg(short = 'd', long, num_args = 0..)]
    decrypt: Vec<String>,
    /// Encrypt files
    #[arg(short = 'e', long, num_args = 0..)]
    encrypt: Vec<String>,
    /// Validate signatures
    #[arg(short = 'V', long, num_args = 0..)]
    validate: Vec<String>,
    /// Sign files
    #[arg(short = 's', long, num_args = 0..)]
    sign: Vec<String>,
    /// Create an embedded signed message
    #[arg(
        short = 'S',
        long = "sign-message",
        num_args = 0..=1,
        default_missing_value = ""
    )]
    sign_message: Option<String>,
    /// Embed metadata from a file in a signed message
    #[arg(short = 'E', long = "embed-meta")]
    embed_meta: Option<String>,
    /// Validate embedded metadata against a spec file
    #[arg(long = "meta-spec")]
    meta_spec: Option<String>,
    /// Sign raw input data instead of hashing first
    #[arg(long)]
    raw: bool,
    /// Output file path
    #[arg(short = 'w', long)]
    write: Option<String>,
    /// Input file for operations that take optional file input
    #[arg(short = 'r', long)]
    read: Option<String>,
    /// Write output even if it overwrites existing files
    #[arg(short = 'f', long)]
    force: bool,
    /// Request unknown identities from the network
    #[arg(short = 'R', long)]
    request: bool,
    /// Never use cached or network-sourced information
    #[arg(short = 'N', long = "no-cache")]
    no_cache: bool,
    /// Identity request timeout before giving up, in seconds
    #[arg(short = 't')]
    timeout: Option<f64>,
    /// Print identity info
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,
    /// Allow displaying private keys
    #[arg(short = 'P', long = "print-private")]
    print_private: bool,
    /// Use base32-encoded input and output
    #[arg(short = 'B', long)]
    base32: bool,
    /// Use base64-encoded input and output
    #[arg(short = 'b', long)]
    base64: bool,
    /// Use base256-encoded input and output
    #[arg(short = 'U', long)]
    base256: bool,
    /// Use hex-encoded input and output
    #[arg(short = 'F', long)]
    hex: bool,
    /// Display RSM metadata if available
    #[arg(long)]
    meta: bool,
}

#[derive(Args)]
struct PathArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Destination hash (32 hexadecimal characters)
    destination: Option<String>,
    /// Filter for a remote blackhole list
    list_filter: Option<String>,
    /// Show all known paths instead of looking one up
    #[arg(short, long)]
    table: bool,
    /// Maximum hops to filter the path table by
    #[arg(short, long)]
    max: Option<u8>,
    /// Show announce rate info
    #[arg(short, long)]
    rates: bool,
    /// Remove the path to a destination
    #[arg(short, long)]
    drop: bool,
    /// Drop all queued announces
    #[arg(short = 'D', long = "drop-announces")]
    drop_announces: bool,
    /// Drop all paths via a transport instance
    #[arg(short = 'x', long = "drop-via")]
    drop_via: bool,
    /// Timeout in seconds before giving up
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// Transport identity hash of a remote instance
    #[arg(short = 'R')]
    remote: Option<String>,
    /// Path to the identity used for remote management
    #[arg(short = 'i')]
    identity: Option<PathBuf>,
    /// Timeout in seconds for remote queries
    #[arg(short = 'W')]
    remote_timeout: Option<f64>,
    /// List blackholed identities
    #[arg(short = 'b', long)]
    blackholed: bool,
    /// Blackhole an identity
    #[arg(short = 'B', long)]
    blackhole: bool,
    /// Remove an identity from the blacklist
    #[arg(short = 'U', long)]
    unblackhole: bool,
    /// Blackhole duration in hours
    #[arg(long)]
    duration: Option<f64>,
    /// Reason stored with a blackhole entry
    #[arg(long)]
    reason: Option<String>,
    /// View a remote transport's published blackhole list
    #[arg(short = 'p', long = "blackholed-list")]
    blackholed_list: bool,
    /// Output in JSON format
    #[arg(short = 'j', long)]
    json: bool,
    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Args)]
struct StatusArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Attach an interface by name
    #[arg(long)]
    attach: Option<String>,
    /// Detach an interface by name
    #[arg(long)]
    detach: Option<String>,
    /// Reload an interface by name
    #[arg(long)]
    reload: Option<String>,
    /// Show interfaces that are normally hidden
    #[arg(short, long)]
    all: bool,
    /// Show link table counts
    #[arg(short = 'l', long = "link-stats")]
    link_stats: bool,
    /// Show traffic totals
    #[arg(short = 't', long)]
    totals: bool,
    /// Show packets per second with totals
    #[arg(short = 'p', long)]
    pps: bool,
    /// Show inbound queue pressure
    #[arg(short = 'q', long)]
    queues: bool,
    /// Show profiling results
    #[arg(short = 'z', long)]
    profiling: bool,
    /// List discovered interfaces
    #[arg(short = 'd', long)]
    discovered: bool,
    /// Show details and config entries for discovered interfaces
    #[arg(short = 'D')]
    config_entries: bool,
    /// Include stale discovery entries
    #[arg(long = "show-stale")]
    show_stale: bool,
    /// Include discovery entries that have no version
    #[arg(long = "show-unknown")]
    show_unknown: bool,
    /// Output in JSON format
    #[arg(short = 'j', long)]
    json: bool,
    /// Transport identity hash of a remote instance
    #[arg(short = 'R')]
    remote: Option<String>,
    /// Path to the identity used for remote management
    #[arg(short = 'i')]
    identity: Option<PathBuf>,
    /// Timeout in seconds for remote queries
    #[arg(short = 'w')]
    timeout: Option<f64>,
    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Only show interfaces whose names contain this text
    filter: Option<String>,
}

#[derive(Args)]
struct CommonArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Args)]
struct XArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Run a command listener
    #[arg(short, long)]
    serve: bool,
    /// Accept commands from anyone
    #[arg(short = 'A', long)]
    allow_all: bool,
    /// Allow this identity hash (repeatable)
    #[arg(short = 'a', long = "allowed")]
    allowed: Vec<String>,
    /// Command to execute remotely
    command: Option<String>,
    /// Same as the positional command (`--command`)
    #[arg(long = "command")]
    command_flag: Option<String>,
    /// Hexadecimal hash of the listener (execute mode)
    #[arg(short, long)]
    destination: Option<String>,
    /// Timeout in seconds
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// Read commands until `exit`, `quit`, or EOF
    #[arg(short = 'x', long)]
    interactive: bool,
    /// Exit with the remote command's status
    #[arg(short = 'm', long)]
    mirror: bool,
    /// Text written to the remote command's stdin
    #[arg(long)]
    stdin: Option<String>,
    /// File whose contents are written to the remote command's stdin
    #[arg(long = "stdin-file")]
    stdin_file: Option<PathBuf>,
    /// Maximum bytes of stdout returned
    #[arg(long)]
    stdout: Option<u64>,
    /// Maximum bytes of stderr returned
    #[arg(long)]
    stderr: Option<u64>,
    /// Debug helper: bind a UDP loopback interface LISTEN:FORWARD
    #[arg(long)]
    udp_loopback: Option<String>,
}

#[derive(Args)]
struct ShArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Run a session listener
    #[arg(short, long)]
    serve: bool,
    /// Accept shell sessions from anyone.
    #[arg(short = 'A', long)]
    allow_all: bool,
    /// Allow this identity hash (repeatable).
    #[arg(short = 'a', long = "allowed")]
    allowed: Vec<String>,
    /// Run one command in a session
    #[arg(short, long)]
    command: Option<String>,
    /// Hexadecimal hash of the listener
    #[arg(short, long)]
    destination: Option<String>,
    /// Debug helper: bind a UDP loopback interface LISTEN:FORWARD
    #[arg(long)]
    udp_loopback: Option<String>,
}

#[derive(Args)]
struct NodeconfArgs {
    /// Serial port of the device
    #[arg(short, long)]
    port: Option<String>,
    /// TCP address of the device
    #[arg(short, long)]
    tcp: Option<String>,
    /// Serial baudrate
    #[arg(short = 'B', long, default_value_t = 115200)]
    baudrate: u32,
    /// Validate the device's radio configuration
    #[arg(long)]
    validate: bool,
    /// Radio frequency in Hz
    #[arg(short, long)]
    frequency: Option<u64>,
    /// Radio bandwidth in Hz
    #[arg(short, long)]
    bandwidth: Option<u32>,
    /// TX power in dBm
    #[arg(short = 'T', long)]
    txpower: Option<u8>,
    /// LoRa spreading factor
    #[arg(short, long)]
    spreadingfactor: Option<u8>,
    /// LoRa coding rate
    #[arg(short, long)]
    codingrate: Option<u8>,
    /// Flash with an external rnodeconf or esptool, if that program is installed
    #[arg(long)]
    flash: bool,
    /// Firmware image for esptool (requires --flash-offset)
    #[arg(long)]
    firmware: Option<PathBuf>,
    /// Flash offset for esptool, decimal or 0x-hex
    #[arg(long)]
    flash_offset: Option<String>,
    /// Baud rate passed to the external flasher
    #[arg(long, default_value_t = 921600)]
    baud_flash: u32,
    /// Switch the device to TNC mode
    #[arg(long)]
    tnc: bool,
    /// Switch the device to normal host-controlled mode
    #[arg(long)]
    normal: bool,
    /// Display intensity, 0-255
    #[arg(long)]
    display: Option<u16>,
    /// Display blanking timeout in seconds, 0 to disable
    #[arg(long)]
    display_timeout: Option<u16>,
    /// Display rotation. Values outside 0 through 3 are clamped.
    #[arg(long, allow_hyphen_values = true)]
    rotation: Option<i64>,
    /// Start display reconditioning
    #[arg(long)]
    recondition_display: bool,
    /// Display address as a hex byte
    #[arg(long)]
    display_addr: Option<String>,
    /// WiFi mode: off, ap, or station
    #[arg(long)]
    wifi: Option<String>,
    /// WiFi channel, 1-14
    #[arg(long)]
    channel: Option<u8>,
    /// WiFi SSID (NONE to delete)
    #[arg(long)]
    ssid: Option<String>,
    /// WiFi PSK (NONE to delete)
    #[arg(long)]
    psk: Option<String>,
    /// Static WiFi address (NONE for DHCP)
    #[arg(long)]
    ip: Option<String>,
    /// Static WiFi netmask (NONE for DHCP)
    #[arg(long)]
    nm: Option<String>,
    /// Turn device bluetooth on
    #[arg(long)]
    bluetooth_on: bool,
    /// Turn device bluetooth off
    #[arg(long)]
    bluetooth_off: bool,
    /// Put the device into bluetooth pairing mode
    #[arg(long)]
    bluetooth_pair: bool,
    /// Read EEPROM and print the decoded image
    #[arg(long)]
    eeprom_dump: bool,
    /// Unlock and wipe EEPROM
    #[arg(long)]
    eeprom_wipe: bool,
}

#[derive(Args)]
struct ProbeArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Hexadecimal hash of the probe destination
    destination: Option<String>,
    /// Full destination name when given after the hash (`app.aspects`)
    aspect_name: Option<String>,
    /// Payload size in bytes
    #[arg(short, long)]
    size: Option<usize>,
    /// Number of probes to send
    #[arg(short, long, default_value_t = 1)]
    probes: usize,
    /// Timeout in seconds before giving up
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// Seconds to wait between probes
    #[arg(long, default_value_t = 0.0)]
    wait: f64,
    /// Full destination name (`app.aspects`), for example `rnstransport.probe`
    #[arg(long = "name")]
    name: Option<String>,
    /// UDP loopback ports LISTEN:FORWARD instead of configured interfaces
    #[arg(long)]
    udp_loopback: Option<String>,
    /// Run a local probe server and probe it once
    #[arg(short, long)]
    loopback: bool,
    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Args)]
struct CpArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// File to transfer (send/fetch mode)
    file: Option<String>,
    /// Hexadecimal hash of the receiver (send/fetch mode)
    destination: Option<String>,
    /// Run a listener accepting files into this directory
    #[arg(short = 'l', long = "serve")]
    serve: Option<PathBuf>,
    /// Fetch the file from the remote instead of sending it
    #[arg(short = 'f', long)]
    fetch: bool,
    /// Print identity and destination info and exit
    #[arg(short = 'p', long)]
    print_identity: bool,
    /// Accept transfers from anyone (no authentication)
    #[arg(short = 'n', long)]
    no_auth: bool,
    /// Allow authenticated clients to fetch files
    #[arg(short = 'F', long)]
    allow_fetch: bool,
    /// Allow this identity hash (repeatable)
    #[arg(short = 'a', long = "allowed")]
    allowed: Vec<String>,
    /// Restrict fetch requests to this path
    #[arg(short = 'j', long)]
    jail: Option<PathBuf>,
    /// Save received files in this path
    #[arg(short = 's', long)]
    save: Option<PathBuf>,
    /// Path to identity to use
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,
    /// Disable automatic compression
    #[arg(short = 'C', long)]
    no_compress: bool,
    /// Disable transfer progress output
    #[arg(short = 'S', long)]
    silent: bool,
    /// Decrease verbosity and suppress transfer progress
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,
    /// Allow overwriting received files instead of adding a numeric suffix
    #[arg(short = 'O', long)]
    overwrite: bool,
    /// Display physical layer transfer rates
    #[arg(short = 'P', long)]
    phy_rates: bool,
    /// Announce interval in seconds (0 = only at startup)
    #[arg(short = 'b', long, default_value_t = 0)]
    announce: u64,
    /// Timeout in seconds before giving up
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// Debug helper: bind a UDP loopback interface BIND:FORWARD instead of
    /// using configured interfaces
    #[arg(long)]
    udp_loopback: Option<String>,
    /// Increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn init_logging(verbosity: i32) {
    // Negative verbosity is quieter than the default `"warn"` filter.
    let level = if verbosity < 0 {
        "error"
    } else {
        match verbosity {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();
}

fn duration_arg(seconds: Option<f64>, default: Duration) -> Duration {
    seconds
        .map(|s| Duration::from_secs_f64(s.max(0.1)))
        .unwrap_or(default)
}

/// Python `main.py` behaviour: dispatch on argv0 when the binary is
/// invoked as `rngit`, `git-remote-rns` or `git-sign-rns` (e.g. via a
/// symlink), so the same executable can serve all entry points. Runs
/// before the shared tokio runtime is created.
fn argv0_dispatch(argv0_name: &str, args: &[String]) -> Option<ExitCode> {
    match argv0_name {
        "git-remote-rns" | "rngit" => {
            init_logging(args.iter().filter(|a| a.as_str() == "-v").count() as i32);
            let args = args.to_vec();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .ok()?;
            let code = match argv0_name {
                "git-remote-rns" => {
                    runtime.block_on(reticulum_utils::rngit::remote_helper_main(&args))
                }
                _ => runtime.block_on(reticulum_utils::rngit::rngit_main(&args)),
            };
            Some(ExitCode::from(code as u8))
        }
        "git-sign-rns" => Some(ExitCode::from(
            reticulum_utils::rngit::commit_sign_main(args) as u8,
        )),
        _ => None,
    }
}

fn main() -> ExitCode {
    if let Some(argv0) = std::env::args().next() {
        if let Some(name) = std::path::Path::new(&argv0)
            .file_name()
            .and_then(|n| n.to_str())
        {
            let args: Vec<String> = std::env::args().collect();
            if let Some(code) = argv0_dispatch(name, &args) {
                return code;
            }
        }
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map(|rt| rt.block_on(run()))
        .unwrap_or_else(|_| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(run())
        })
}

async fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Id(args) => {
            let options = IdOptions {
                generate: args.generate,
                identity: args.identity,
                public: args.public,
                no_save: false,
                config: args.config,
                import_pub: args.import_pub,
                import_prv: args.import_prv,
                export_pub: args.export_pub,
                export_prv: args.export_prv,
                verbose: args.verbose,
                quiet: args.quiet,
                announce: args.announce,
                hash: args.hash,
                decrypt: args.decrypt,
                encrypt: args.encrypt,
                validate: args.validate,
                sign: args.sign,
                sign_message: args.sign_message,
                embed_meta: args.embed_meta,
                meta_spec: args.meta_spec,
                raw: args.raw,
                write: args.write,
                read: args.read,
                force: args.force,
                request: args.request,
                no_cache: args.no_cache,
                timeout: args.timeout,
                print_identity: args.print_identity,
                print_private: args.print_private,
                base32: args.base32,
                base64: args.base64,
                base256: args.base256,
                hex: args.hex,
                meta: args.meta,
            };
            match reticulum_utils::rnid::execute(options).await {
                Ok(code) => ExitCode::from(code as u8),
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(reticulum_utils::rnid::R_INVALID_IDENTITY as u8)
                }
            }
        }
        Command::Path(args) => exit_code(run_path(args).await),
        Command::Status(args) => exit_code(run_status(args).await),
        Command::Cp(args) => exit_code(run_cp(args).await),
        Command::Probe(args) => exit_code(run_probe(args).await),
        Command::X(args) => exit_code(run_x(args).await),
        Command::Sh(args) => exit_code(run_sh(args).await),
        Command::Git { args } => {
            init_logging(0);
            let mut argv = vec!["rngit".to_string()];
            argv.extend(args);
            ExitCode::from(reticulum_utils::rngit::rngit_main(&argv).await as u8)
        }
        Command::GitSign { args } => {
            let mut argv = vec!["git-sign-rns".to_string()];
            argv.extend(args);
            ExitCode::from(reticulum_utils::rngit::commit_sign_main(&argv) as u8)
        }
        #[cfg(feature = "iface-rnode")]
        Command::NodeSim(args) => {
            init_logging(1);
            if let Err(err) = reticulum_utils::rnode_sim::run(args).await {
                eprintln!("{err}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }

        Command::Nodeconf(args) => {
            #[cfg(feature = "iface-rnode")]
            {
                exit_code(run_nodeconf(args).await)
            }
            #[cfg(not(feature = "iface-rnode"))]
            {
                let _ = args;
                eprintln!("rnodeconf requires building with --features iface-rnode");
                ExitCode::FAILURE
            }
        }
        Command::Ir(args) => {
            init_logging(0);
            let options = reticulum_utils::rnir::Options {
                config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            };
            exit_code(reticulum_utils::rnir::run(&options).await)
        }
        Command::Pkg(args) => {
            init_logging(0);
            let options = reticulum_utils::rnpkg::Options {
                config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            };
            exit_code(reticulum_utils::rnpkg::run(&options).await)
        }
    }
}

fn exit_code(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

async fn run_path(args: PathArgs) -> Result<(), String> {
    init_logging(args.verbose as i32);
    if !args.drop_announces
        && !args.table
        && !args.rates
        && args.destination.is_none()
        && !args.drop_via
        && !args.blackholed
        && !args.blackholed_list
    {
        println!(
            "No destination specified. Use -t/--table, -r/--rates, -b/--blackholed, or pass a destination hash."
        );
        return Ok(());
    }
    let config_dir = reticulum_utils::common::resolve_config_dir(args.config.as_deref());
    let remote_timeout = duration_arg(
        args.remote_timeout,
        reticulum_utils::rnpath::DEFAULT_TIMEOUT,
    );

    if args.blackholed_list && !args.blackholed {
        let (_, hash) = require_destination(&args.destination)?;
        let transport = path_transport(&config_dir).await;
        let text = reticulum_utils::rnpath::remote_blackhole_list(
            &transport,
            &hash,
            remote_timeout,
            args.list_filter.as_deref(),
            reticulum_utils::common::unix_now(),
        )
        .await?;
        print!("{text}");
        return Ok(());
    }

    if let Some(remote) = &args.remote {
        return run_remote_path(&args, &config_dir, remote, remote_timeout).await;
    }

    let transport = path_transport(&config_dir).await;
    let attached = transport
        .iface_manager()
        .lock()
        .await
        .connected_to_shared_instance();
    if attached {
        run_instance_path(&args, &config_dir, None).await
    } else {
        run_instance_path(&args, &config_dir, Some(&transport)).await
    }
}

async fn path_transport(config_dir: &std::path::Path) -> reticulum::transport::Transport {
    reticulum_utils::common::build_tool_transport(reticulum_utils::common::ToolTransportOptions {
        config_dir,
        instance_name: "rnpath",
        enable_transport: false,
        udp_loopback: None,
    })
    .await
}

fn require_destination(
    destination: &Option<String>,
) -> Result<(String, reticulum::hash::AddressHash), String> {
    let shown = destination
        .as_deref()
        .ok_or_else(|| "No destination specified".to_string())?;
    Ok((shown.to_string(), parse_hash(shown)?))
}

fn load_management_identity(
    path: &Option<PathBuf>,
) -> Result<reticulum::identity::PrivateIdentity, String> {
    let Some(path) = path else {
        return Err("Could not load management identity from None".to_string());
    };
    reticulum_utils::common::load_private_identity(path).map_err(|err| {
        format!(
            "Could not load management identity from {}: {err}",
            path.display()
        )
    })
}

async fn run_remote_path(
    args: &PathArgs,
    config_dir: &std::path::Path,
    remote: &str,
    timeout: Duration,
) -> Result<(), String> {
    let identity_hash = parse_hash(remote)?;
    let identity = load_management_identity(&args.identity)?;
    let transport = path_transport(config_dir).await;
    let filter = match &args.destination {
        Some(destination) => Some(parse_hash(destination)?),
        None => None,
    };
    // Python connects to the management destination before these stubs.
    // A missing identity, path timeout, or link failure happens first.
    if let Some(message) = remote_unsupported(args) {
        let destination = reticulum_utils::rnpath::named_destination(
            "rnstransport",
            "remote.management",
            &identity_hash,
        );
        reticulum_utils::rnpath::connect_remote(
            &transport,
            &destination,
            Some(&identity),
            timeout,
            !args.json,
        )
        .await?;
        return Err(message.to_string());
    }
    if args.table {
        let text = if args.json {
            reticulum_utils::rnpath::remote_path_json(
                &transport,
                &identity_hash,
                &identity,
                filter.as_ref(),
                args.max,
                timeout,
            )
            .await?
        } else {
            reticulum_utils::rnpath::remote_path_table(
                &transport,
                &identity_hash,
                &identity,
                filter.as_ref(),
                args.max,
                timeout,
            )
            .await?
        };
        if args.json {
            println!("{text}");
        } else {
            print!("{text}");
        }
        return Ok(());
    }
    if args.rates {
        let text = if args.json {
            reticulum_utils::rnpath::remote_rates_json(
                &transport,
                &identity_hash,
                &identity,
                filter.as_ref(),
                timeout,
            )
            .await?
        } else {
            reticulum_utils::rnpath::remote_rates(
                &transport,
                &identity_hash,
                &identity,
                filter.as_ref(),
                reticulum_utils::common::unix_now(),
                timeout,
            )
            .await?
        };
        if args.json {
            println!("{text}");
        } else {
            print!("{text}");
        }
        return Ok(());
    }
    Err("Requesting paths on remote instances not implemented".to_string())
}

fn remote_unsupported(args: &PathArgs) -> Option<&'static str> {
    if args.blackholed {
        Some("Listing blackholed identities on remote instances not yet implemented")
    } else if args.blackhole || args.unblackhole {
        Some("Blackholing identity on remote instances not yet implemented")
    } else if args.table || args.rates {
        None
    } else if args.drop_announces {
        Some("Dropping announce queues on remote instances not yet implemented")
    } else if args.drop {
        Some("Dropping path on remote instances not yet implemented")
    } else if args.drop_via {
        Some(
            "Dropping all paths via specific transport instance on remote instances yet not implemented",
        )
    } else {
        Some("Requesting paths on remote instances not implemented")
    }
}

async fn run_instance_path(
    args: &PathArgs,
    config_dir: &std::path::Path,
    local: Option<&reticulum::transport::Transport>,
) -> Result<(), String> {
    let filter = match &args.destination {
        Some(destination) => Some(parse_hash(destination)?),
        None => None,
    };
    let now = reticulum_utils::common::unix_now();
    if args.blackholed {
        let text = match local {
            Some(transport) => {
                reticulum_utils::rnpath::local_blackholed_text(
                    transport,
                    args.destination.as_deref(),
                    now,
                )
                .await?
            }
            None => {
                reticulum_utils::rnpath::blackholed_text(
                    config_dir,
                    args.destination.as_deref(),
                    now,
                    None,
                )
                .await?
            }
        };
        print!("{text}");
        return Ok(());
    }
    if args.blackhole {
        let (shown, hash) = require_destination(&args.destination)?;
        let until = args.duration.map(|hours| now + hours * 3_600.0);
        let text = match local {
            Some(transport) => {
                reticulum_utils::rnpath::local_blackhole_text(
                    transport,
                    &hash,
                    &shown,
                    until,
                    args.reason.clone(),
                )
                .await?
            }
            None => {
                reticulum_utils::rnpath::blackhole_text(
                    config_dir,
                    &hash,
                    &shown,
                    until,
                    args.reason.as_deref(),
                )
                .await?
            }
        };
        println!("{text}");
        return Ok(());
    }
    if args.unblackhole {
        let (shown, hash) = require_destination(&args.destination)?;
        let text = match local {
            Some(transport) => {
                reticulum_utils::rnpath::local_unblackhole_text(transport, &hash, &shown).await?
            }
            None => reticulum_utils::rnpath::unblackhole_text(config_dir, &hash, &shown).await?,
        };
        println!("{text}");
        return Ok(());
    }
    if args.table {
        if args.json {
            let value = match local {
                Some(transport) => {
                    reticulum_utils::rnpath::local_path_table_value(transport, args.max).await?
                }
                None => reticulum_utils::rnpath::path_table_value(config_dir, args.max).await?,
            };
            println!("{}", reticulum_utils::common::msgpack_json(&value));
        } else {
            let text = match local {
                Some(transport) => {
                    reticulum_utils::rnpath::local_path_table_text(
                        transport,
                        filter.as_ref(),
                        args.max,
                    )
                    .await?
                }
                None => {
                    reticulum_utils::rnpath::path_table_text(config_dir, filter.as_ref(), args.max)
                        .await?
                }
            };
            print!("{text}");
        }
        return Ok(());
    }
    if args.rates {
        if args.json {
            let value = match local {
                Some(transport) => reticulum_utils::rnpath::local_rates_value(transport, now).await,
                None => reticulum_utils::rnpath::rates_value(config_dir).await?,
            };
            println!("{}", reticulum_utils::common::msgpack_json(&value));
        } else {
            let text = match local {
                Some(transport) => {
                    reticulum_utils::rnpath::local_rates_text(transport, filter.as_ref(), now)
                        .await?
                }
                None => {
                    reticulum_utils::rnpath::rates_text(config_dir, filter.as_ref(), now).await?
                }
            };
            print!("{text}");
        }
        return Ok(());
    }
    if args.drop_announces {
        let text = match local {
            Some(transport) => reticulum_utils::rnpath::local_drop_announces_text(transport).await,
            None => reticulum_utils::rnpath::drop_announces_text(config_dir).await?,
        };
        println!("{text}");
        return Ok(());
    }
    if args.drop {
        let (_, hash) = require_destination(&args.destination)?;
        let text = match local {
            Some(transport) => {
                reticulum_utils::rnpath::local_drop_path_text(transport, &hash).await?
            }
            None => reticulum_utils::rnpath::drop_path_text(config_dir, &hash).await?,
        };
        println!("{text}");
        return Ok(());
    }
    if args.drop_via {
        let (_, hash) = require_destination(&args.destination)?;
        let text = match local {
            Some(transport) => {
                reticulum_utils::rnpath::local_drop_via_text(transport, &hash).await?
            }
            None => reticulum_utils::rnpath::drop_via_text(config_dir, &hash).await?,
        };
        println!("{text}");
        return Ok(());
    }
    let timeout = duration_arg(args.timeout, reticulum_utils::rnpath::DEFAULT_TIMEOUT);
    if let Some(transport) = local {
        lookup_path(transport, &args.destination, timeout).await
    } else {
        let transport = path_transport(config_dir).await;
        lookup_path(&transport, &args.destination, timeout).await
    }
}

async fn lookup_path(
    transport: &reticulum::transport::Transport,
    destination: &Option<String>,
    timeout: Duration,
) -> Result<(), String> {
    let (_, hash) = require_destination(destination)?;
    match reticulum_utils::rnpath::wait_for_path(transport, &hash, timeout).await {
        Some(result) => {
            println!("{}", result.render());
            Ok(())
        }
        None => Err("Path not found".to_string()),
    }
}

async fn run_status(args: StatusArgs) -> Result<(), String> {
    init_logging(args.verbose as i32);
    let config_dir = reticulum_utils::common::resolve_config_dir(args.config.as_deref());
    let view = reticulum_utils::rnstatus::StatusView {
        show_all: args.all,
        link_stats: args.link_stats,
        totals: args.totals,
        pps: args.pps,
        queues: args.queues,
        profiling: args.profiling,
        discovered_only: args.discovered || args.config_entries,
        config_entries: args.config_entries,
        show_stale: args.show_stale,
        show_unknown: args.show_unknown,
        json: args.json,
        name_filter: args.filter.clone(),
    };

    if let Some(action) = manage_action(&args) {
        let transport = reticulum_utils::common::build_tool_transport_requiring_shared(
            reticulum_utils::common::ToolTransportOptions {
                config_dir: &config_dir,
                instance_name: "rnstatus",
                enable_transport: false,
                udp_loopback: None,
            },
        )
        .await?;
        let (verb, name) = action;
        let message = reticulum_utils::rnstatus::manage_interface(&config_dir, verb, name).await?;
        println!("{message}");
        drop(transport);
        return Ok(());
    }

    if let Some(remote) = &args.remote {
        if view.discovered_only {
            let text = reticulum_utils::rnstatus::local_discovery(&config_dir, &view).await;
            print!("{text}");
            return Ok(());
        }
        if args.identity.is_none() {
            return Err(
                "Remote management requires an identity file. Use -i to specify the path to a management identity."
                    .to_string(),
            );
        }
        let identity = load_management_identity(&args.identity)?;
        let hash = parse_hash(remote)?;
        let transport = reticulum_utils::common::build_tool_transport(
            reticulum_utils::common::ToolTransportOptions {
                config_dir: &config_dir,
                instance_name: "rnstatus",
                enable_transport: false,
                udp_loopback: None,
            },
        )
        .await;
        let text = reticulum_utils::rnstatus::remote_status(
            &transport,
            &hash,
            &identity,
            &view,
            duration_arg(args.timeout, reticulum_utils::rnpath::DEFAULT_TIMEOUT),
        )
        .await?;
        print!("{text}");
        return Ok(());
    }

    let transport = reticulum_utils::common::build_tool_transport_requiring_shared(
        reticulum_utils::common::ToolTransportOptions {
            config_dir: &config_dir,
            instance_name: "rnstatus",
            enable_transport: false,
            udp_loopback: None,
        },
    )
    .await?;
    let text = reticulum_utils::rnstatus::fetch_status(&config_dir, &view).await?;
    print!("{text}");
    drop(transport);
    Ok(())
}

fn manage_action(args: &StatusArgs) -> Option<(&str, &str)> {
    if let Some(name) = args.attach.as_deref() {
        return Some(("attach", name));
    }
    if let Some(name) = args.detach.as_deref() {
        return Some(("detach", name));
    }
    if let Some(name) = args.reload.as_deref() {
        return Some(("reload", name));
    }
    None
}

async fn run_cp(args: CpArgs) -> Result<(), String> {
    init_logging(args.verbose as i32 - args.quiet as i32);
    let timeout = duration_arg(args.timeout, reticulum_utils::rncp::DEFAULT_TIMEOUT);
    let udp_loopback = args.udp_loopback.as_deref().and_then(parse_udp_loopback);

    let config_dir = reticulum_utils::common::resolve_config_dir(args.config.as_deref());
    if args.print_identity {
        let (identity, destination) =
            reticulum_utils::rncp::print_identity(&config_dir, args.identity.as_deref()).await?;
        println!("Identity     : {identity}");
        println!("Listening on : {destination}");
        return Ok(());
    }

    if let Some(dir) = &args.serve {
        let allowed = args
            .allowed
            .iter()
            .map(|hash| parse_hash(hash))
            .collect::<Result<Vec<_>, _>>()?;
        let options = ServeOptions {
            config_dir: args.config.clone(),
            save_dir: dir.clone(),
            allowed,
            no_auth: args.no_auth,
            allow_fetch: args.allow_fetch,
            jail: args.jail.clone(),
            announce_interval: args.announce,
            no_compress: args.no_compress,
            identity_path: args.identity.clone(),
            udp_loopback,
            allow_overwrite: args.overwrite,
        };
        return reticulum_utils::rncp::serve(options).await;
    }

    let (file, destination) =
        match (&args.file, &args.destination) {
            (Some(file), Some(destination)) => (file.clone(), parse_hash(destination)?),
            _ => return Err(
                "Nothing to do: pass <file> <destination> to send, --fetch <file> <destination> \
                 to fetch, or --serve <dir> to listen."
                    .to_string(),
            ),
        };

    if args.fetch {
        let options = FetchOptions {
            config_dir: args.config.clone(),
            file,
            destination,
            timeout,
            silent: args.silent,
            save_dir: args.save.clone(),
            identity_path: args.identity.clone(),
            udp_loopback,
            quiet: args.quiet > 0,
            phy_rates: args.phy_rates,
            allow_overwrite: args.overwrite,
        };
        let message = reticulum_utils::rncp::fetch(options).await?;
        println!("{message}");
    } else {
        let options = SendOptions {
            config_dir: args.config.clone(),
            file: PathBuf::from(file),
            destination,
            timeout,
            no_compress: args.no_compress,
            silent: args.silent,
            identity_path: args.identity.clone(),
            udp_loopback,
            quiet: args.quiet > 0,
            phy_rates: args.phy_rates,
        };
        let message = reticulum_utils::rncp::send(options).await?;
        println!("{message}");
    }
    Ok(())
}

fn parse_udp_loopback(spec: &str) -> Option<(u16, u16)> {
    let (bind, forward) = spec.split_once(':')?;
    Some((bind.parse().ok()?, forward.parse().ok()?))
}

async fn run_probe(args: ProbeArgs) -> Result<(), String> {
    init_logging(args.verbose as i32);

    if args.loopback {
        let (destination, results) = reticulum_utils::rnprobe::run_loopback()
            .await
            .map_err(|err| format!("probe failed: {err:?}"))?;
        print!(
            "{}",
            reticulum_utils::rnprobe::render_results(&destination, &results)
        );
        return Ok(());
    }

    let (destination_text, aspect_name) =
        probe_target(args.destination, args.aspect_name, args.name)?;
    let destination = parse_hash(&destination_text)?;

    let udp_loopback = parse_udp_pair(args.udp_loopback.as_deref());

    let options = reticulum_utils::rnprobe::ProbeOptions {
        config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
        size: args
            .size
            .unwrap_or(reticulum_utils::rnprobe::DEFAULT_PROBE_SIZE),
        timeout: duration_arg(args.timeout, reticulum_utils::rnprobe::DEFAULT_TIMEOUT),
        probes: args.probes,
        udp_loopback,
        wait: Duration::from_secs_f64(args.wait.max(0.0)),
        full_name: aspect_name,
    };

    let results = reticulum_utils::rnprobe::probe(&destination, &options)
        .await
        .map_err(|err| format!("probe failed: {err:?}"))?;

    print!(
        "{}",
        reticulum_utils::rnprobe::render_results(&destination, &results)
    );
    Ok(())
}

fn probe_target(
    destination: Option<String>,
    aspect_name: Option<String>,
    name_flag: Option<String>,
) -> Result<(String, Option<String>), String> {
    let aspect = name_flag.or(aspect_name);
    match (destination, aspect) {
        (None, _) => Err("a destination hash is required (or use --loopback)".to_string()),
        (Some(first), Some(second)) if first.contains('.') && !second.contains('.') => {
            Ok((second, Some(first)))
        }
        (Some(first), second) => {
            if first.contains('.') && second.is_none() {
                return Err("a destination hash is required (or use --loopback)".to_string());
            }
            Ok((first, second))
        }
    }
}

fn parse_udp_pair(spec: Option<&str>) -> Option<(u16, u16)> {
    let spec = spec?;
    let (listen, forward) = spec.split_once(':')?;
    Some((listen.parse().ok()?, forward.parse().ok()?))
}

async fn run_x(args: XArgs) -> Result<(), String> {
    init_logging(1);

    let udp_loopback = parse_udp_pair(args.udp_loopback.as_deref());

    if args.serve {
        let options = reticulum_utils::rnx::ServeOptions {
            config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            allow_all: args.allow_all,
            allowed: args
                .allowed
                .iter()
                .map(|hash| parse_hash(hash))
                .collect::<Result<_, _>>()?,
            udp_loopback,
            idle_timeout: None,
        };

        let address = reticulum_utils::rnx::serve(&options).await?;
        println!("rnx listening on {address}");
        return Ok(());
    }

    let destination = args
        .destination
        .as_deref()
        .map(parse_hash)
        .transpose()
        .map_err(|e| e.to_string())?
        .ok_or("a destination hash is required")?;

    let stdin = match (&args.stdin, &args.stdin_file) {
        (Some(_), Some(_)) => {
            return Err("pass only one of --stdin and --stdin-file".to_string());
        }
        (inline, file) => reticulum_utils::rnx::stdin_payload(inline.as_deref(), file.as_deref())?,
    };
    let options = reticulum_utils::rnx::ExecOptions {
        config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
        timeout: duration_arg(args.timeout, std::time::Duration::from_secs(30)),
        udp_loopback,
        stdin,
        stdout_limit: args.stdout,
        stderr_limit: args.stderr,
    };

    let mut last_code = 0i32;
    if let Some(command) = args.command_flag.as_deref().or(args.command.as_deref()) {
        last_code = run_remote_command(
            &destination,
            command,
            &options,
            args.mirror && !args.interactive,
            args.interactive,
        )
        .await?;
    } else if !args.interactive {
        return Err("a command is required (or use --serve)".to_string());
    }

    if args.interactive {
        let mut loop_options = options.clone();
        loop_options.stdin = None;
        let stdin = std::io::stdin();
        loop {
            if args.mirror && last_code != 0 {
                print!("{last_code}> ");
            } else {
                print!("> ");
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let mut line = String::new();
            if stdin.read_line(&mut line).map_err(|err| err.to_string())? == 0 {
                break;
            }
            let command = line.trim();
            if command.is_empty() {
                continue;
            }
            if command.eq_ignore_ascii_case("exit") || command.eq_ignore_ascii_case("quit") {
                break;
            }
            if command.eq_ignore_ascii_case("clear") {
                // RIS, same sequence as Python `print('\033c')`.
                print!("\x1bc");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                continue;
            }
            match run_remote_command(&destination, command, &loop_options, false, true).await {
                Ok(code) => last_code = code,
                Err(err) => return Err(err),
            }
        }
    }

    Ok(())
}

async fn run_remote_command(
    destination: &reticulum::hash::AddressHash,
    command: &str,
    options: &reticulum_utils::rnx::ExecOptions,
    mirror: bool,
    interactive: bool,
) -> Result<i32, String> {
    let result = match reticulum_utils::rnx::execute(destination, command, options).await {
        Ok(result) => result,
        Err(err)
            if interactive
                && (err.contains("could not execute")
                    || err.contains("did not execute")
                    || err.contains("no result")
                    || err.contains("no response")
                    || err.contains("invalid response")) =>
        {
            eprintln!("{err}");
            return Ok(0);
        }
        Err(err) => return Err(err),
    };
    print!("{}", String::from_utf8_lossy(&result.stdout));
    if !result.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&result.stderr));
    }
    let truncated = (options.stdout_limit != Some(0)
        && (result.stdout.len() as u64) < result.stdout_len)
        || (options.stderr_limit != Some(0) && (result.stderr.len() as u64) < result.stderr_len);
    if truncated {
        eprintln!("\nOutput truncated before being returned:");
        if !result.stdout.is_empty() && (result.stdout.len() as u64) < result.stdout_len {
            eprintln!("  stdout truncated to {} bytes", result.stdout.len());
        }
        if !result.stderr.is_empty() && (result.stderr.len() as u64) < result.stderr_len {
            eprintln!("  stderr truncated to {} bytes", result.stderr.len());
        }
    }
    if !result.executed {
        let message = "Remote could not execute command";
        eprintln!("{message}");
        if interactive {
            return Ok(0);
        }
        std::process::exit(248);
    }
    if !result.has_retval {
        if mirror {
            std::process::exit(240);
        }
        return Ok(0);
    }
    let code = reticulum_utils::rnx::remote_exit_code(&result);
    if mirror && code != 0 {
        std::process::exit(code);
    }
    Ok(code)
}

async fn run_sh(args: ShArgs) -> Result<(), String> {
    init_logging(1);

    let udp_loopback = parse_udp_pair(args.udp_loopback.as_deref());
    let allowed = args
        .allowed
        .iter()
        .map(|hash| parse_hash(hash).map_err(|err| err.to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    if args.serve {
        let options = reticulum_utils::rnsh::ServeOptions {
            config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            allow_all: args.allow_all,
            allowed,
            default_command: None,
            allow_remote_command: true,
            udp_loopback,
        };

        let address = reticulum_utils::rnsh::serve(&options).await?;
        println!("rnsh listening on {address}");
        return Ok(());
    }

    let destination = args
        .destination
        .as_deref()
        .map(parse_hash)
        .transpose()
        .map_err(|e| e.to_string())?
        .ok_or("a destination hash is required")?;

    let options = reticulum_utils::rnsh::ServeOptions {
        config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
        allow_all: false,
        allowed: Vec::new(),
        default_command: None,
        allow_remote_command: true,
        udp_loopback,
    };

    // `--command` stays a non-interactive capture. With no command, run a
    // session against the listener's shell.
    let Some(command) = args.command.as_deref() else {
        let code = reticulum_utils::rnsh::run_interactive(&destination, None, &options).await?;
        std::process::exit(code);
    };

    let outcome = reticulum_utils::rnsh::run_command(&destination, command, &options).await?;
    {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(&outcome.stdout);
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(&outcome.stderr);
    }
    if let Some(code) = outcome.exit_code {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(feature = "iface-rnode")]
fn host_failure(action: &str, err: reticulum::error::RnsError) -> String {
    match err {
        reticulum::error::RnsError::ResourceMsg(msg) => msg.to_string(),
        err => format!("{action} failed: {err:?}"),
    }
}

#[cfg(feature = "iface-rnode")]
fn optional_text(value: &str) -> Option<&str> {
    if value.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(value)
    }
}

#[cfg(feature = "iface-rnode")]
async fn run_nodeconf(args: NodeconfArgs) -> Result<(), String> {
    use reticulum_utils::rnodeconf::{
        bluetooth_host_frames, display_address_sequence, display_blanking_frame,
        display_intensity_frame, display_recondition_frame, display_rotation_frame,
        enter_normal_mode, enter_tnc_mode, flash_command, parse_eeprom, read_eeprom, render_eeprom,
        render_info, transact, wifi_channel_frame, wifi_ip_frame, wifi_mode_code, wifi_mode_frame,
        wifi_nm_frame, wifi_psk_frame, wifi_ssid_frame, wipe_eeprom, BT_CTRL_OFF, BT_CTRL_ON,
        BT_CTRL_PAIR,
    };

    init_logging(1);

    if args.flash {
        let port = args.port.as_deref().ok_or("flash needs a serial --port")?;
        let offset = match args.flash_offset.as_deref() {
            Some(text) => {
                let text = text.trim();
                let parsed = if let Some(hex) =
                    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
                {
                    u32::from_str_radix(hex, 16)
                } else {
                    text.parse()
                };
                Some(parsed.map_err(|_| format!("invalid --flash-offset {text}"))?)
            }
            None => None,
        };
        let cmd = flash_command(port, args.baud_flash, args.firmware.as_deref(), offset)?;
        let status = std::process::Command::new(&cmd.program)
            .args(&cmd.args)
            .status()
            .map_err(|err| format!("failed to run {}: {err}", cmd.program.display()))?;
        if !status.success() {
            return Err(format!("{} exited with {status}", cmd.program.display()));
        }
        return Ok(());
    }

    let target = if let Some(tcp) = args.tcp.as_deref() {
        reticulum_utils::rnodeconf::DeviceTarget::Tcp {
            addr: tcp.to_string(),
        }
    } else if let Some(port) = args.port.as_deref() {
        reticulum_utils::rnodeconf::DeviceTarget::Serial {
            port: port.to_string(),
            baudrate: args.baudrate,
        }
    } else {
        return Err("a --port or --tcp target is required".to_string());
    };

    if args.validate {
        let frequency = args
            .frequency
            .ok_or("--frequency is required for validation")?;
        let config = reticulum::iface::rnode::RnodeRadioConfig {
            frequency,
            bandwidth: args.bandwidth.ok_or("--bandwidth is required")?,
            txpower: args.txpower.ok_or("--txpower is required")?,
            spreadingfactor: args
                .spreadingfactor
                .ok_or("--spreadingfactor is required")?,
            codingrate: args.codingrate.ok_or("--codingrate is required")?,
            st_alock: None,
            lt_alock: None,
        };
        return match reticulum_utils::rnodeconf::validate_config(&target, &config).await {
            Ok(_) => {
                println!("Radio configuration validated");
                Ok(())
            }
            Err(err) => Err(format!("validation failed: {err:?}")),
        };
    }

    if args.eeprom_wipe {
        wipe_eeprom(&target)
            .await
            .map_err(|err| format!("EEPROM wipe failed: {err:?}"))?;
        println!("EEPROM wipe sent");
        return Ok(());
    }

    let mut frames = Vec::new();
    if let Some(level) = args.display {
        frames.extend(display_intensity_frame(level.min(255) as u8));
    }
    if let Some(timeout) = args.display_timeout {
        frames.extend(display_blanking_frame(timeout.min(255) as u8));
    }
    if let Some(rotation) = args.rotation {
        let rotation = rotation.clamp(0, 3) as u8;
        frames.extend(display_rotation_frame(rotation));
    }
    if args.recondition_display {
        frames.extend(display_recondition_frame());
    }
    if let Some(addr) = args.display_addr.as_deref() {
        let text = addr
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let byte =
            u8::from_str_radix(text, 16).map_err(|_| format!("invalid display address {addr}"))?;
        frames.extend(display_address_sequence(byte));
        transact(&target, &frames)
            .await
            .map_err(|err| format!("configuration failed: {err:?}"))?;
        println!("Display address set");
        return Ok(());
    }
    if args.bluetooth_on {
        frames.extend(bluetooth_host_frames(BT_CTRL_ON));
    }
    if args.bluetooth_off {
        frames.extend(bluetooth_host_frames(BT_CTRL_OFF));
    }
    if args.bluetooth_pair {
        frames.extend(bluetooth_host_frames(BT_CTRL_PAIR));
    }
    if let Some(channel) = args.channel {
        frames.extend(
            wifi_channel_frame(channel)
                .map_err(|_| "WiFi channel must be 1 through 14".to_string())?,
        );
    }
    if let Some(ssid) = args.ssid.as_deref() {
        frames.extend(
            wifi_ssid_frame(optional_text(ssid)).map_err(|_| "invalid WiFi SSID".to_string())?,
        );
    }
    if let Some(psk) = args.psk.as_deref() {
        frames.extend(
            wifi_psk_frame(optional_text(psk)).map_err(|_| "invalid WiFi PSK".to_string())?,
        );
    }
    if let Some(ip) = args.ip.as_deref() {
        frames.extend(
            wifi_ip_frame(optional_text(ip)).map_err(|_| "invalid WiFi IP address".to_string())?,
        );
    }
    if let Some(mask) = args.nm.as_deref() {
        frames.extend(
            wifi_nm_frame(optional_text(mask)).map_err(|_| "invalid WiFi netmask".to_string())?,
        );
    }
    if let Some(mode) = args.wifi.as_deref() {
        frames.extend(wifi_mode_frame(wifi_mode_code(mode)));
    }

    let mut acted = false;
    if !frames.is_empty() {
        transact(&target, &frames)
            .await
            .map_err(|err| format!("configuration failed: {err:?}"))?;
        println!("configuration frames sent");
        acted = true;
    }

    if args.eeprom_dump {
        match read_eeprom(&target)
            .await
            .map_err(|err| format!("EEPROM read failed: {err:?}"))?
        {
            Some(image) => match parse_eeprom(&image) {
                Some(map) => print!("{}", render_eeprom(&map)),
                None => println!("EEPROM image ({} bytes) could not be parsed", image.len()),
            },
            None => println!("no EEPROM image in reply"),
        }
        acted = true;
    }

    if args.normal {
        enter_normal_mode(&target)
            .await
            .map_err(|err| host_failure("normal mode", err))?;
        println!("Device set to normal (host-controlled) operating mode");
        return Ok(());
    }

    if args.tnc {
        let config = reticulum::iface::rnode::RnodeRadioConfig {
            frequency: args.frequency.ok_or("--frequency is required")?,
            bandwidth: args.bandwidth.ok_or("--bandwidth is required")?,
            txpower: args.txpower.ok_or("--txpower is required")?,
            spreadingfactor: args
                .spreadingfactor
                .ok_or("--spreadingfactor is required")?,
            codingrate: args.codingrate.ok_or("--codingrate is required")?,
            st_alock: None,
            lt_alock: None,
        };
        enter_tnc_mode(&target, &config)
            .await
            .map_err(|err| host_failure("TNC mode", err))?;
        println!("Device set to TNC operating mode");
        return Ok(());
    }

    if acted {
        return Ok(());
    }

    let info = reticulum_utils::rnodeconf::device_info(&target)
        .await
        .map_err(|e| format!("device probe failed: {e:?}"))?;
    print!("{}", render_info(&info));
    Ok(())
}
