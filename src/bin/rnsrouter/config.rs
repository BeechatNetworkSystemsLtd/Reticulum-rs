use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::path::Path;
use std::fs;

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
        transport_identity: String,
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
    /// convert_python_config converts the non-standard Python config to real toml
    fn convert_python_config(content: &str) -> String {
        let mut output = String::new();

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
            converted = converted.replace(" = True", " = true");
            converted = converted.replace(" = False", " = false");
            converted = converted.replace(" = Yes", " = true");
            converted = converted.replace(" = yes", " = true");
            converted = converted.replace(" = No", " = false");
            converted = converted.replace(" = no", " = false");

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
                converted = quote_if_needed(&converted, "transport_identity");
            }

            output.push_str(&converted);
            output.push('\n');
        }

        output
    }

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

    pub fn migrate_config(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        println!("Migrating old rnsd configuration ({}) to standard toml...", path.display());
        let old_config = std::fs::read_to_string(path.join("config"))?;
        let content = Self::convert_python_config(&old_config);
        fs::write(path.join("config.toml"), content)?;
        Ok(())
    }

    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.join("config.toml").exists() && path.join("config").exists() {
            Self::migrate_config(&path)?;
        }

        let config_file = path.join("config.toml");
        if !config_file.exists() {
            println!("Error: Please configure rncdaemon via ~/.config/reticulum/config.toml");
            return Err("Missing configuration".into())
        }
        let content = std::fs::read_to_string(&config_file)?;
        let config: Config = toml::from_str(&content)?;

        if config.reticulum.share_instance {
            log::warn!("share_instance is enabled but shared instances are not supported in reticulum-rs");
            log::warn!("Each Rust daemon process runs independently and is only limited by available ports");
        }

        Ok(config)
    }

    pub fn load() -> Result<(Self, PathBuf), Box<dyn std::error::Error>> {
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
