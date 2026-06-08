use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub reticulum: ReticulumConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub interfaces: Vec<NamedInterface>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReticulumConfig {
    #[serde(default)]
    pub enable_transport: bool,
    #[serde(default = "default_true")]
    pub share_instance: bool,
    #[serde(default = "default_shared_port")]
    pub shared_instance_port: u16,
    #[serde(default = "default_control_port")]
    pub instance_control_port: u16,
    #[serde(default)]
    pub panic_on_interface_error: bool,
    #[serde(default)]
    pub instance_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_loglevel")]
    pub loglevel: log::LevelFilter,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NamedInterface {
    pub name: String,
    #[serde(flatten)]
    pub config: InterfaceConfig,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum InterfaceConfig {
    TCPServerInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        #[serde(alias = "listen_ip")]
        bind_host: String,
        #[serde(alias = "listen_port")]
        bind_port: u16,
    },
    TCPClientInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        target_host: String,
        target_port: u16,
    },
    UDPInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        listen_ip: String,
        listen_port: u16,
        forward_ip: String,
        forward_port: u16,
    },
    AutoInterface {
        #[serde(default = "default_true")]
        enabled: bool,
    },
    I2PInterface {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default)]
        connectable: bool,
        peers: String,
    },
    RNodeInterface {
        #[serde(default = "default_true", alias = "interface_enabled")]
        enabled: bool,
        port: String,
        frequency: u64,
        bandwidth: u32,
        txpower: u8,
        spreadingfactor: u8,
        codingrate: u8,
        #[serde(default)]
        flow_control: bool,
    },
    BLEInterface {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default)]
        enable_peripheral: bool,
        #[serde(default)]
        enable_central: bool,
    },
    KISSInterface {
        #[serde(default = "default_true")]
        enabled: bool,
        port: String,
        speed: u32,
        databits: u8,
        parity: String,
        stopbits: u8,
        preamble: u32,
        txtail: u32,
        persistence: u32,
        slottime: u32,
        #[serde(default)]
        flow_control: bool,
    },
    AX25KISSInterface {
        #[serde(default = "default_true")]
        enabled: bool,
        callsign: String,
        ssid: u8,
        port: String,
        speed: u32,
        databits: u8,
        parity: String,
        stopbits: u8,
        preamble: u32,
        txtail: u32,
        persistence: u32,
        slottime: u32,
        #[serde(default)]
        flow_control: bool,
    },
    #[serde(other)]
    Unsupported,
}

fn default_true() -> bool { true }
fn default_shared_port() -> u16 { 37428 }
fn default_control_port() -> u16 { 37429 }
fn default_loglevel() -> log::LevelFilter { log::LevelFilter::Info }

pub fn migrate_config(config_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !config_file.exists() {
        eprintln!("Error: File '{}' does not exist", config_file.display());
        std::process::exit(1);
    }
    println!("Reading config from: {}", config_file.display());
    let content = fs::read_to_string(config_file)?;
    if toml::from_str::<Config>(&content).is_ok() {
        println!("File is already a valid TOML config: exiting");
        return Ok(())
    }
    let converted = convert_config(&content);
    // validate
    match toml::from_str::<toml::Value>(&converted) {
        Ok(_) => {}
        Err(err) => {
            eprintln!("error: converted text is not a valid TOML file");
            return Err(err.into())
        }
    }
    if cfg!(debug_assertions) {
        match toml::from_str::<Config>(&converted) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("error: converted text is not a valid rs-rnsd Config file");
                return Err(err.into())
            }
        }
    }
    // in case the passed-in file already has a .toml extension, create a backup to prevent
    // overwriting it
    let new_config_file = if config_file.extension() == Some(OsStr::new("toml")) {
        let backup_path = config_file.with_extension("bak");
        fs::write(&backup_path, &content)?;
        println!("Created backup at: {}", backup_path.display());
        config_file.to_owned()
    } else {
        config_file.with_extension("toml")
    };
    fs::write(&new_config_file, &converted)?;
    println!("✓ Converted config written to: {}", new_config_file.display());
    println!();
    println!("Changes made:");
    println!("  - Converted numeric log level to log level string");
    println!("  - Converted True/False/Yes/No → true/false");
    println!("  - Quoted all string values (IPs, hostnames, paths, types)");
    println!("  - Converted [[Interface Name]] → [[interfaces]] with name field");
    println!("  - Normalized indentation");
    println!("  - Preserved all comments");
    Ok(())
}

fn convert_config(content: &str) -> String {
    fn quote_if_needed(line: &str, key: &str) -> String {
        let pattern = format!("{} = ", key);
        let quoted_pattern = format!("{} = \"", key);
        // Already quoted or not present
        if !line.contains(&pattern) || line.contains(&quoted_pattern) {
            return line.to_string();
        }
        // Find the value
        if let Some(pos) = line.find(&pattern) {
            let value_start = pos + pattern.len();
            let rest = &line[value_start..];
            let value = rest.split_whitespace().next().unwrap_or(rest).trim();
            // Don't quote numbers or booleans
            if value.parse::<i64>().is_ok() || value.parse::<f64>().is_ok() 
                || value == "true" || value == "false" {
                return line.to_string();
            }
            // Quote the value
            format!("{}{} = \"{}\"", &line[..pos], key, value)
        } else {
            line.to_string()
        }
    }

    let mut output = String::new();
    let re_false = Regex::new(r" = \b(No|no|False)\b").unwrap();
    let re_true = Regex::new(r" = \b(Yes|yes|True)\b").unwrap();
    let re_nil = Regex::new(r"^(\w+)\s*=\s*\b(None|none|nil|Nil|null|Null)\b").unwrap();
    let re_loglevel = Regex::new(r"(\bloglevel\s*=\s*)(\d+)\b").unwrap();
    for line in content.lines() {
        let trimmed = line.trim();
        // Empty lines pass through
        if trimmed.is_empty() {
            output.push('\n');
            continue;
        }
        // Skip [interfaces] header - we use [[interfaces]] instead
        if trimmed == "[interfaces]" {
            continue;
        }
        // Detect interface block start
        if trimmed.starts_with("[[") && trimmed.ends_with("]]") {
            let name = trimmed.trim_start_matches("[[").trim_end_matches("]]").trim();
            if name != "interfaces" {
                // Convert [[Interface Name]] to [[interfaces]]
                output.push_str("\n[[interfaces]]\n");
                output.push_str(&format!("name = \"{}\"\n", name));
                continue;
            } else {
                output.push_str("\n[[interfaces]]\n");
                continue;
            }
        }
        // Process the line
        let mut converted = trimmed.to_string();
        // Convert booleans
        converted = re_false.replace_all(&converted, " = false").to_string();
        converted = re_true.replace_all(&converted, " = true").to_string();
        // Comment out nil values, as toml does not support them (https://github.com/toml-lang/toml/issues/30)
        if re_nil.is_match(&converted) {
            converted = format!("# {}", converted);
            output.push_str(&converted);
            output.push('\n');
            continue;
        }

        // Convert numeric loglevel
        converted = re_loglevel.replace(&converted, |caps: &regex::Captures| {
            let level_num: u8 = caps[2].parse().unwrap();
            let level = python_log_filter(level_num);
            let out = format!("{}{}", &caps[1], level);
            out
        }).to_string();

        // Quote unquoted string values (only for non-comments)
        if !converted.starts_with('#') {
            converted = quote_if_needed(&converted, "type");
            converted = quote_if_needed(&converted, "remote");
            converted = quote_if_needed(&converted, "target_host");
            converted = quote_if_needed(&converted, "bind_host");
            converted = quote_if_needed(&converted, "listen_ip");
            converted = quote_if_needed(&converted, "forward_ip");
            converted = quote_if_needed(&converted, "peers");
            converted = quote_if_needed(&converted, "instance_name");
            converted = quote_if_needed(&converted, "port");
            converted = quote_if_needed(&converted, "callsign");
            converted = quote_if_needed(&converted, "parity");
            converted = quote_if_needed(&converted, "loglevel");
        }
        output.push_str(&converted);
        output.push('\n');
    }
    output
}

impl Default for ReticulumConfig {
    fn default() -> Self {
        Self {
            enable_transport: false,
            share_instance: false,
            shared_instance_port: 37428,
            instance_control_port: 37429,
            panic_on_interface_error: false,
            instance_name: None,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { loglevel: default_loglevel() }
    }
}

impl Config {
    pub fn search_paths() -> Vec<PathBuf> {
        let mut paths = vec![];
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(".config/reticulum"));
            paths.push(home.join(".reticulum"));
        }
        paths.push(PathBuf::from("/etc/reticulum"));
        paths
    }

    pub fn find_existing() -> Option<PathBuf> {
        Self::search_paths()
            .into_iter()
            .find(|p| p.join("config").exists() || p.join("config.toml").exists())
    }

    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .expect("home directory")
            .join(".config/reticulum")
    }

    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let config_basename = if path.join("config.toml").exists() {
            "config.toml"
        } else if path.join("config").exists() {
            "config"
        } else {
            let err = format!("no config.toml or config file found in config path {}",
                path.display());
            return Err(err.into())
        };
        let config_file = path.join(config_basename);
        let content = fs::read_to_string(&config_file)?;
        let config: Self = match toml::from_str(&content) {
            Ok(config) => config,
            Err(err) => {
                if config_basename == "config.toml" {
                    eprintln!("{config_file:?} is not valid TOML");
                    return Err(err.into())
                } else {
                    // attempt to convert
                    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    eprintln!("Your config file appears to be in Python Reticulum format.");
                    eprintln!("You can use the converter tool to migrate it to standard TOML:");
                    eprintln!();
                    eprintln!("  cargo run -p reticulum-daemon -- convert-config {}", config_file.display());
                    eprintln!();
                    eprintln!("This command will create a backup and convert your config to valid TOML.");
                    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    let converted = convert_config(&content);
                    toml::from_str(&converted)?
                }
            }
        };
        if config.reticulum.share_instance {
            log::warn!("share_instance is enabled but shared instances are not supported in reticulum-rs");
            log::warn!("Each Rust daemon process runs independently and is only limited by available ports");
        }
        Ok(config)
    }

    pub fn load(custom_config_path: Option<&Path>) -> Result<(Self, PathBuf), Box<dyn std::error::Error>> {
        if let Some(path) = custom_config_path {
            let config = Self::from_file(path)?;
            return Ok((config, path.to_path_buf()));
        }
        if let Some(existing) = Self::find_existing() {
            let config = Self::from_file(&existing)?;
            Ok((config, existing))
        } else {
            log::warn!("No existing configuration found, creating default config");
            let default_dir = Self::default_path();
            fs::create_dir_all(&default_dir)?;
            let config = Self::default_config();
            let config_file = default_dir.join("config.toml");
            fs::write(&config_file, toml::to_string_pretty(&config)?)?;
            log::warn!("Created default configuration at: {}", config_file.display());
            log::warn!("Please review and customize the configuration for your needs");
            Ok((config, default_dir))
        }
    }

    fn default_config() -> Self {
        Self {
            reticulum: ReticulumConfig::default(),
            logging: LoggingConfig::default(),
            interfaces: vec![
                NamedInterface {
                    name: "Default TCP Server Interface".to_string(),
                    config: InterfaceConfig::TCPServerInterface {
                        enabled: true,
                        bind_host: "127.0.0.1".to_string(),
                        bind_port: 4242,
                    },
                },
            ],
        }
    }
}

pub fn python_log_filter(loglevel: u8) -> log::LevelFilter {
    match loglevel {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Info,
        5 => log::LevelFilter::Debug,
        6 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}
