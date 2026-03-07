use serde::{Deserialize, Serialize};
use std::path;
use std::path::PathBuf;
use std::path::Path;

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
    pub loglevel: u8,
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
fn default_loglevel() -> u8 { 4 }

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
        Self { loglevel: 4 }
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
        let config_file = if path.join("config").exists() {
            path.join("config")
        } else {
            path.join("config.toml")
        };
        
        let content = std::fs::read_to_string(&config_file)?;
        let config: Self = toml::from_str(&content).inspect_err(|_e| {
            eprintln!();
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!("INVALID TOML FORMAT");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!();
            eprintln!("Your config file appears to be in Python Reticulum format.");
            eprintln!("Use the converter tool to migrate it to standard TOML:");
            eprintln!();
            eprintln!("  cargo run --example convert_config -- {}", config_file.display());
            eprintln!();
            eprintln!("This will create a backup and convert your config to valid TOML.");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            eprintln!();
        })?;
        
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
            std::fs::create_dir_all(&default_dir)?;
            
            let config = Self::default_config();
            let config_file = default_dir.join("config.toml");
            std::fs::write(&config_file, toml::to_string_pretty(&config)?)?;
            
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

    pub fn log_filter(&self) -> &'static str {
        match self.logging.loglevel {
            0 => "error",
            1 => "error",
            2 => "warn",
            3 => "info",
            4 => "info",
            5 => "debug",
            6 => "debug",
            _ => "trace",
        }
    }
}
