//! `rn id` — Reticulum identity utility (`RNS/Utilities/rnid.py`).
//!
//! Generate, inspect, import/export, sign, validate, encrypt, decrypt,
//! destination hashes, announces and shared-instance path requests.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, NAME_HASH_LENGTH};
use reticulum::hash::{AddressHash, Hash as ContentHash};
use reticulum::identity::{Identity, PrivateIdentity, Signature};
use reticulum::transport::{Transport, PATH_REQUEST_TIMEOUT};
use sha2::Digest;

use crate::common::{
    identity_from_raw_keys, load_private_identity, prettyhexrep, save_private_identity,
};

pub const R_OK: i32 = 0;
pub const R_NO_IDENTITY: i32 = 2;
pub const R_NO_PUBKEY: i32 = 3;
pub const R_NO_PRVKEY: i32 = 4;
pub const R_NO_KEYS: i32 = 5;
pub const R_NO_FILE: i32 = 6;
pub const R_INVALID_FILE: i32 = 7;
pub const R_INVALID_IDENTITY: i32 = 8;
pub const R_INVALID_ASPECTS: i32 = 9;
pub const R_INVALID_SIGNATURE: i32 = 10;
pub const R_FILE_EXISTS: i32 = 11;
pub const R_DECRYPT_FAILED: i32 = 12;
pub const R_INVALID_ARGS: i32 = 250;
pub const R_READ_ERROR: i32 = 252;
pub const R_WRITE_ERROR: i32 = 253;
pub const R_UNKNOWN_ERROR: i32 = 254;

const KEY_BYTES: usize = reticulum::identity::PUBLIC_KEY_LENGTH * 2;
const SIG_BYTES: usize = 64;
const ENC_CHUNK: usize = 1024 * 1024 * 16;
const DEC_CHUNK: usize = ENC_CHUNK + 96;
const DEFAULT_ASPECTS: &str = "rns.id";

/// What `rn id` should do.
#[derive(Debug, Default, Clone)]
pub struct IdOptions {
    /// `-g/--generate <path>`: generate a new identity and save it.
    pub generate: Option<PathBuf>,
    /// `-i/--identity <path|hex>`: operating identity, or a 16-byte hash.
    pub identity: Option<String>,
    /// `--public`: basic inspect prints only public key material.
    pub public: bool,
    /// Generate without saving even when a path is implied.
    pub no_save: bool,
    /// `--config`.
    pub config: Option<PathBuf>,
    /// `-m/--import-pub`.
    pub import_pub: Option<String>,
    /// `-M/--import-prv`.
    pub import_prv: Option<String>,
    /// `-x/--export-pub`.
    pub export_pub: bool,
    /// `-X/--export-prv`.
    pub export_prv: bool,
    pub verbose: u8,
    pub quiet: u8,
    /// `-a/--announce`. `Some("rns.id")` is the flag with no value.
    pub announce: Option<String>,
    /// `-H/--hash`.
    pub hash: Option<String>,
    /// `-d/--decrypt`.
    pub decrypt: Vec<String>,
    /// `-e/--encrypt`.
    pub encrypt: Vec<String>,
    /// `-V/--validate`.
    pub validate: Vec<String>,
    /// `-s/--sign`.
    pub sign: Vec<String>,
    /// `-S/--sign-message`. Empty string launches `$EDITOR`.
    pub sign_message: Option<String>,
    /// `-E/--embed-meta`.
    pub embed_meta: Option<String>,
    /// `--meta-spec`.
    pub meta_spec: Option<String>,
    /// `--raw`.
    pub raw: bool,
    /// `-w/--write`.
    pub write: Option<String>,
    /// `-r/--read`.
    pub read: Option<String>,
    /// `-f/--force`.
    pub force: bool,
    /// `-R/--request`.
    pub request: bool,
    /// `-N/--no-cache`.
    pub no_cache: bool,
    /// `-t` seconds.
    pub timeout: Option<f64>,
    /// `-p/--print-identity`.
    pub print_identity: bool,
    /// `-P/--print-private`.
    pub print_private: bool,
    /// `-B/--base32`.
    pub base32: bool,
    /// `-b/--base64`.
    pub base64: bool,
    /// `-U/--base256`.
    pub base256: bool,
    /// `-F/--hex`.
    pub hex: bool,
    /// `--meta`.
    pub meta: bool,
}

/// A rendered identity report (basic generate / inspect).
#[derive(Debug, PartialEq, Eq)]
pub struct IdentityInfo {
    pub hash: String,
    pub public_key: String,
    pub verifying_key: String,
    pub private_key: Option<String>,
    pub saved_to: Option<String>,
    pub loaded_from: Option<String>,
}

impl IdentityInfo {
    /// Render like the historical `rn id` report.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Identity     : {}\n", self.hash));
        if let Some(source) = &self.loaded_from {
            out.push_str(&format!("Loaded From  : {source}\n"));
        }
        out.push_str(&format!("Public Key   : {}\n", self.public_key));
        out.push_str(&format!("Verifying Key: {}\n", self.verifying_key));
        if let Some(private) = &self.private_key {
            out.push_str(&format!("Private Key  : {private}\n"));
        }
        if let Some(path) = &self.saved_to {
            out.push_str(&format!("Saved To     : {path}\n"));
        }
        out
    }
}

/// Run `rn id` for operations that do not touch the network.
///
/// Announce and `-R` return an error here; [`execute`] runs those.
pub fn run(options: IdOptions) -> Result<i32, String> {
    if is_basic(&options) {
        return run_basic(options);
    }
    if needs_network(&options) {
        return Err("announce and path requests need the async rnid entry point".into());
    }
    if let Some(code) = reject_args(&options) {
        return Ok(code);
    }
    let config_dir = crate::common::resolve_config_dir(options.config.as_deref());
    let resolved = match resolve_sync(&options, &config_dir) {
        Ok(resolved) => resolved,
        Err(code) => return Ok(code),
    };
    if op_requires(&options) && resolved.key.is_none() {
        println!("Could not get working identity");
        return Ok(R_NO_IDENTITY);
    }
    let (code, did) = run_sections(&options, &resolved, Section::All)?;
    if code != 0 {
        return Ok(code);
    }
    if !did {
        print_usage();
    }
    Ok(R_OK)
}

/// Run `rn id`, including announce and shared-instance path requests.
pub async fn execute(options: IdOptions) -> Result<i32, String> {
    if is_basic(&options) {
        return run_basic(options);
    }
    if !needs_network(&options) {
        return run(options);
    }
    if let Some(code) = reject_args(&options) {
        return Ok(code);
    }
    // Announce and `-R` build a transport. Match the other `rn` tools:
    // `-v` raises the level and `-q` lowers it, before that transport exists.
    let verbosity = options.verbose.saturating_sub(options.quiet);
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .try_init();
    let config_dir = crate::common::resolve_config_dir(options.config.as_deref());
    let resolved = match resolve_async(&options, &config_dir).await {
        Ok(resolved) => resolved,
        Err(code) => return Ok(code),
    };
    if op_requires(&options) && resolved.key.is_none() {
        println!("Could not get working identity");
        return Ok(R_NO_IDENTITY);
    }

    let transport = if options.announce.is_some() {
        Some(
            crate::common::build_tool_transport(crate::common::ToolTransportOptions {
                config_dir: &config_dir,
                instance_name: "rnid",
                enable_transport: false,
                udp_loopback: None,
            })
            .await,
        )
    } else {
        None
    };

    let (code, mut did) = run_sections(&options, &resolved, Section::Before)?;
    if code != 0 {
        return Ok(code);
    }
    if let Some(aspects) = options.announce.clone() {
        let Some(transport) = transport.as_ref() else {
            return Err("announce transport was not started".into());
        };
        let code = announce(transport, &resolved, &aspects).await?;
        if code != 0 {
            return Ok(code);
        }
        did = true;
    }
    let (code, did_after) = run_sections(&options, &resolved, Section::After)?;
    if code != 0 {
        return Ok(code);
    }
    did |= did_after;
    if !did {
        print_usage();
    }
    Ok(R_OK)
}

fn needs_network(options: &IdOptions) -> bool {
    options.announce.is_some() || options.request
}

fn is_basic(options: &IdOptions) -> bool {
    options.import_pub.is_none()
        && options.import_prv.is_none()
        && !options.export_pub
        && !options.export_prv
        && options.verbose == 0
        && options.quiet == 0
        && options.announce.is_none()
        && options.hash.is_none()
        && options.decrypt.is_empty()
        && options.encrypt.is_empty()
        && options.validate.is_empty()
        && options.sign.is_empty()
        && options.sign_message.is_none()
        && options.embed_meta.is_none()
        && options.meta_spec.is_none()
        && !options.raw
        && options.write.is_none()
        && options.read.is_none()
        && !options.force
        && !options.request
        && !options.no_cache
        && options.timeout.is_none()
        && !options.print_identity
        && !options.print_private
        && !options.base32
        && !options.base64
        && !options.base256
        && !options.hex
        && !options.meta
}

fn op_requires(options: &IdOptions) -> bool {
    options.sign_message.is_some()
        || !options.sign.is_empty()
        || !options.encrypt.is_empty()
        || !options.decrypt.is_empty()
        || options.announce.is_some()
        || options.write.is_some()
        || options.print_identity
        || options.export_pub
        || options.export_prv
}

fn reject_args(options: &IdOptions) -> Option<i32> {
    let ops = [
        !options.encrypt.is_empty(),
        !options.decrypt.is_empty(),
        !options.validate.is_empty(),
        !options.sign.is_empty(),
        options.sign_message.is_some(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    if ops > 1 {
        println!(
            "This utility currently only supports one of the encrypt, decrypt, sign or verify operations per invocation"
        );
        return Some(1);
    }
    let sources = [
        options.import_pub.is_some(),
        options.import_prv.is_some(),
        options.identity.is_some(),
        options.generate.is_some(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    if sources > 1 {
        println!("The -i, -g, -m and -M args are mutually exclusive");
        return Some(1);
    }
    let formats = [options.base64, options.base32, options.base256, options.hex]
        .into_iter()
        .filter(|set| *set)
        .count();
    if formats > 1 {
        println!("The -b, -B, --hex and --base256 args are mutually exclusive");
        return Some(1);
    }
    None
}

fn print_usage() {
    println!("Reticulum Identity & Encryption Utility");
    println!(
        "Usage: rn id [-g path] [-i identity] [-m pub] [-M prv] [-x|-X] [-a [aspects]] [-H aspects] [-e file...] [-d file...] [-s file...] [-S [text]] [-V path...] [-w path] [-R]"
    );
}

fn run_basic(options: IdOptions) -> Result<i32, String> {
    if options.generate.is_some() && options.identity.is_some() {
        return Err("The --generate and --identity options are mutually exclusive".to_string());
    }

    if let Some(path) = options.generate.clone() {
        if path.exists() {
            return Err(format!(
                "Identity file {} already exists. Not overwriting.",
                path.display()
            ));
        }
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut info = info_for_private(&identity, &options);
        if !options.no_save {
            save_private_identity(&path, &identity).map_err(|err| {
                format!("An error occurred while saving the generated identity: {err}")
            })?;
            info.saved_to = Some(path.display().to_string());
        }
        print!("{}", info.render());
        return Ok(0);
    }

    if let Some(identity_arg) = &options.identity {
        let path = Path::new(identity_arg);
        let info = if path.is_file() {
            let identity = load_private_identity(path)
                .map_err(|err| format!("Could not load Identity from specified file: {err}"))?;
            let mut info = info_for_private(&identity, &options);
            info.loaded_from = Some(path.display().to_string());
            info
        } else {
            let cleaned = identity_arg.trim();
            if options.public {
                let identity = Identity::new_from_hex_string(cleaned)
                    .map_err(|_| "Could not parse the specified public identity".to_string())?;
                IdentityInfo {
                    hash: prettyhexrep(identity.address_hash.as_slice()),
                    public_key: hex_encode(identity.public_key_bytes()),
                    verifying_key: hex_encode(identity.verifying_key_bytes()),
                    private_key: None,
                    saved_to: None,
                    loaded_from: None,
                }
            } else {
                let identity = PrivateIdentity::new_from_hex_string(cleaned)
                    .map_err(|_| "Could not parse the specified identity".to_string())?;
                info_for_private(&identity, &options)
            }
        };
        print!("{}", info.render());
        return Ok(0);
    }

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let info = info_for_private(&identity, &options);
    print!("{}", info.render());
    Ok(0)
}

fn info_for_private(identity: &PrivateIdentity, options: &IdOptions) -> IdentityInfo {
    IdentityInfo {
        hash: prettyhexrep(identity.address_hash().as_slice()),
        public_key: hex_encode(identity.as_identity().public_key_bytes()),
        verifying_key: hex_encode(identity.as_identity().verifying_key_bytes()),
        private_key: if options.public {
            None
        } else {
            Some(identity.to_hex_string())
        },
        saved_to: None,
        loaded_from: None,
    }
}

/// Build an identity from raw private key bytes.
pub fn from_raw_keys(bytes: &[u8]) -> Option<PrivateIdentity> {
    identity_from_raw_keys(bytes)
}

#[derive(Clone)]
enum KeyMaterial {
    Private(Box<PrivateIdentity>),
    Public(Box<Identity>),
}

impl KeyMaterial {
    fn public_identity(&self) -> &Identity {
        match self {
            Self::Private(identity) => identity.as_identity(),
            Self::Public(identity) => identity,
        }
    }

    fn private_key(&self) -> Option<&PrivateIdentity> {
        match self {
            Self::Private(identity) => Some(identity),
            Self::Public(_) => None,
        }
    }

    fn hash(&self) -> &AddressHash {
        &self.public_identity().address_hash
    }

    fn label(&self) -> String {
        prettyhexrep(self.hash().as_slice())
    }

    fn public_bytes(&self) -> [u8; KEY_BYTES] {
        self.public_identity().to_bytes()
    }

    fn private_bytes(&self) -> Option<[u8; KEY_BYTES]> {
        self.private_key().map(PrivateIdentity::to_bytes)
    }
}

struct Resolved {
    key: Option<KeyMaterial>,
    identity_arg: Option<String>,
    requested_hash: Option<AddressHash>,
}

enum Section {
    Before,
    After,
    All,
}

fn run_sections(
    options: &IdOptions,
    resolved: &Resolved,
    section: Section,
) -> Result<(i32, bool), String> {
    let before = matches!(section, Section::Before | Section::All);
    let after = matches!(section, Section::After | Section::All);
    let mut did = false;
    if before {
        if options.print_identity {
            let code = print_identity_information(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if options.export_pub {
            let code = export_public(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if options.export_prv {
            let code = export_private(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if options.hash.is_some() {
            let code = print_hash_information(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
    }
    if after {
        if !options.validate.is_empty() {
            let code = validate_paths(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if !options.sign.is_empty() {
            let code = sign_paths(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if options.sign_message.is_some() {
            let code = sign_message(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if !options.encrypt.is_empty() {
            let code = encrypt_paths(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if !options.decrypt.is_empty() {
            let code = decrypt_paths(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if options.write.is_some() {
            let code = write_identity(options, resolved)?;
            if code != 0 {
                return Ok((code, true));
            }
            did = true;
        }
        if options.generate.is_some() {
            did = true;
        }
    }
    Ok((0, did))
}

fn resolve_sync(options: &IdOptions, config_dir: &Path) -> Result<Resolved, i32> {
    if let Some(path) = &options.generate {
        return generate_identity(path, options.force);
    }
    if let Some(import) = &options.import_pub {
        return import_public(import);
    }
    if let Some(import) = &options.import_prv {
        return import_private(import);
    }
    if let Some(identity) = &options.identity {
        return load_identity_arg(identity, options, config_dir);
    }
    Ok(Resolved {
        key: None,
        identity_arg: None,
        requested_hash: None,
    })
}

async fn resolve_async(options: &IdOptions, config_dir: &Path) -> Result<Resolved, i32> {
    if options.generate.is_some() || options.import_pub.is_some() || options.import_prv.is_some() {
        return resolve_sync(options, config_dir);
    }
    let Some(identity) = &options.identity else {
        return Ok(Resolved {
            key: None,
            identity_arg: None,
            requested_hash: None,
        });
    };
    let path = expand_user(identity);
    if path.is_file() {
        return load_identity_file(&path);
    }
    // `-N` skips cache and network recall. A hash is still the required
    // signer for `-V` and embedded messages.
    let requested = unresolved_hash(identity)?;
    if options.no_cache {
        if op_requires(options) {
            println!("Could not resolve identity");
            return Err(R_NO_IDENTITY);
        }
        return Ok(Resolved {
            key: None,
            identity_arg: Some(identity.clone()),
            requested_hash: Some(requested),
        });
    }
    if let Some(found) = recall_from_disk(config_dir, &requested) {
        print_recalled(&found, &requested);
        let _ = retain_identity(config_dir, found.address_hash).await;
        return Ok(Resolved {
            key: Some(KeyMaterial::Public(Box::new(found))),
            identity_arg: Some(identity.clone()),
            requested_hash: Some(requested),
        });
    }
    if !options.request {
        if op_requires(options) {
            println!(
                "Could not recall Identity for {}.",
                prettyhexrep(requested.as_slice())
            );
            println!("You can query the network for unknown Identities with the -R option.");
            return Err(R_NO_IDENTITY);
        }
        return Ok(Resolved {
            key: None,
            identity_arg: Some(identity.clone()),
            requested_hash: Some(requested),
        });
    }

    let timeout = match options.timeout {
        None => PATH_REQUEST_TIMEOUT,
        Some(seconds) => path_request_timeout(seconds)?,
    };
    let id_destination = destination_hash(DEFAULT_ASPECTS, requested.as_slice());
    let transport = crate::common::build_tool_transport(crate::common::ToolTransportOptions {
        config_dir,
        instance_name: "rnid",
        enable_transport: false,
        udp_loopback: None,
    })
    .await;
    request_identity_paths(&transport, config_dir, &[requested, id_destination]).await;
    println!(
        "Requesting unknown Identity for {}",
        prettyhexrep(requested.as_slice())
    );
    let deadline = std::time::Instant::now() + timeout;
    let found = loop {
        if let Some(identity) =
            recall_loaded(&transport, config_dir, &requested, &id_destination).await
        {
            break Some(identity);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let Some(found) = found else {
        println!("Identity request timed out");
        if op_requires(options) {
            return Err(R_NO_IDENTITY);
        }
        return Ok(Resolved {
            key: None,
            identity_arg: Some(identity.clone()),
            requested_hash: Some(requested),
        });
    };
    println!(
        "Received Identity {} for destination {} from the network",
        prettyhexrep(found.address_hash.as_slice()),
        prettyhexrep(requested.as_slice())
    );
    let _ = retain_identity(config_dir, found.address_hash).await;
    Ok(Resolved {
        key: Some(KeyMaterial::Public(Box::new(found))),
        identity_arg: Some(identity.clone()),
        requested_hash: Some(requested),
    })
}

fn load_identity_arg(
    identity: &str,
    options: &IdOptions,
    config_dir: &Path,
) -> Result<Resolved, i32> {
    let path = expand_user(identity);
    if path.is_file() {
        return load_identity_file(&path);
    }
    let requested = unresolved_hash(identity)?;
    if options.no_cache {
        if op_requires(options) {
            println!("Could not resolve identity");
            return Err(R_NO_IDENTITY);
        }
        return Ok(Resolved {
            key: None,
            identity_arg: Some(identity.to_string()),
            requested_hash: Some(requested),
        });
    }
    if let Some(found) = recall_from_disk(config_dir, &requested) {
        print_recalled(&found, &requested);
        return Ok(Resolved {
            key: Some(KeyMaterial::Public(Box::new(found))),
            identity_arg: Some(identity.to_string()),
            requested_hash: Some(requested),
        });
    }
    if options.request {
        return Err(R_NO_IDENTITY);
    }
    if op_requires(options) {
        println!(
            "Could not recall Identity for {}.",
            prettyhexrep(requested.as_slice())
        );
        println!("You can query the network for unknown Identities with the -R option.");
        return Err(R_NO_IDENTITY);
    }
    Ok(Resolved {
        key: None,
        identity_arg: Some(identity.to_string()),
        requested_hash: Some(requested),
    })
}

/// A non-file `-i` is a 16-byte hex hash. Anything else is not an identity.
fn unresolved_hash(identity: &str) -> Result<AddressHash, i32> {
    if identity.len() != 32 {
        println!("Invalid identity hash length");
        return Err(R_INVALID_IDENTITY);
    }
    match parse_hex_hash(identity) {
        Some(hash) => Ok(hash),
        None => {
            println!("Invalid hexadecimal hash provided: {identity}");
            Err(R_INVALID_IDENTITY)
        }
    }
}

/// Finite non-positive values wait zero time. Non-finite and overflowing
/// values are rejected so `Duration` is never built from them.
fn path_request_timeout(seconds: f64) -> Result<Duration, i32> {
    if !seconds.is_finite() {
        println!("Invalid identity request timeout");
        return Err(R_INVALID_ARGS);
    }
    if seconds <= 0.0 {
        return Ok(Duration::ZERO);
    }
    match Duration::try_from_secs_f64(seconds) {
        Ok(duration) => Ok(duration),
        Err(_) => {
            println!("Invalid identity request timeout");
            Err(R_INVALID_ARGS)
        }
    }
}

fn print_recalled(identity: &Identity, requested: &AddressHash) {
    let ident = prettyhexrep(identity.address_hash.as_slice());
    let hash = prettyhexrep(requested.as_slice());
    if ident == hash {
        println!("Recalled Identity {ident}");
    } else {
        println!("Recalled Identity {ident} for destination {hash}");
    }
}

fn load_identity_file(path: &Path) -> Result<Resolved, i32> {
    match load_private_identity(path) {
        Ok(identity) => {
            println!(
                "Loaded Identity {} from {}",
                prettyhexrep(identity.address_hash().as_slice()),
                path.display()
            );
            Ok(Resolved {
                key: Some(KeyMaterial::Private(Box::new(identity))),
                identity_arg: Some(path.display().to_string()),
                requested_hash: None,
            })
        }
        Err(err) => {
            println!("Could not load Identity from specified file: {err}");
            Err(R_INVALID_IDENTITY)
        }
    }
}

fn generate_identity(path: &Path, force: bool) -> Result<Resolved, i32> {
    if path.is_file() && !force {
        println!(
            "Identity file {} already exists. Not overwriting.",
            path.display()
        );
        return Err(R_FILE_EXISTS);
    }
    let identity = PrivateIdentity::new_from_rand(OsRng);
    match save_private_identity(path, &identity) {
        Ok(()) => {
            println!(
                "New identity {} written to {}",
                prettyhexrep(identity.address_hash().as_slice()),
                path.display()
            );
            Ok(Resolved {
                key: Some(KeyMaterial::Private(Box::new(identity))),
                identity_arg: None,
                requested_hash: None,
            })
        }
        Err(err) => {
            println!("An error ocurred while saving the generated Identity: {err}");
            Err(R_WRITE_ERROR)
        }
    }
}

fn import_public(import: &str) -> Result<Resolved, i32> {
    let bytes = decode_key_material(import, true)?;
    if bytes.len() != KEY_BYTES {
        println!("Could not decode specified data to a valid public Reticulum Identity");
        return Err(R_INVALID_IDENTITY);
    }
    let identity = Identity::new_from_slices(&bytes[..32], &bytes[32..]);
    // `new_from_slices` substitutes a default verifying key when the bytes
    // are not a real Ed25519 key. Keep the imported bytes or reject them.
    if identity.to_bytes().as_slice() != bytes.as_slice() {
        println!("Could not create Reticulum identity from specified data");
        return Err(R_INVALID_IDENTITY);
    }
    Ok(Resolved {
        key: Some(KeyMaterial::Public(Box::new(identity))),
        identity_arg: None,
        requested_hash: None,
    })
}

fn import_private(import: &str) -> Result<Resolved, i32> {
    let bytes = decode_key_material(import, false)?;
    if bytes.len() != KEY_BYTES {
        println!("Could not decode specified data to a valid private Reticulum Identity");
        return Err(R_INVALID_IDENTITY);
    }
    match PrivateIdentity::new_from_bytes(&bytes) {
        Ok(identity) => Ok(Resolved {
            key: Some(KeyMaterial::Private(Box::new(identity))),
            identity_arg: None,
            requested_hash: None,
        }),
        Err(err) => {
            println!("Could not create Reticulum identity from specified data: {err:?}");
            Err(R_INVALID_IDENTITY)
        }
    }
}

fn decode_key_material(import: &str, public: bool) -> Result<Vec<u8>, i32> {
    let kind = if public { "public" } else { "private" };
    let path = expand_user(import);
    if path.is_file() {
        if let Ok(file) = std::fs::read(&path) {
            if file.len() == KEY_BYTES {
                println!("Reticulum Identity imported from {}", path.display());
                return Ok(file);
            }
        }
    }
    if import.len() == KEY_BYTES * 2 {
        if let Some(bytes) = decode_hex(import) {
            if bytes.len() == KEY_BYTES {
                println!("Reticulum Identity imported from hex input");
                return Ok(bytes);
            }
        }
    }
    if let Some(bytes) = b32_decode(import) {
        if bytes.len() == KEY_BYTES {
            println!("Reticulum Identity imported from base32 input");
            return Ok(bytes);
        }
    }
    if let Some(bytes) = b64_decode(import) {
        if bytes.len() == KEY_BYTES {
            println!("Reticulum Identity imported from base64 input");
            return Ok(bytes);
        }
    }
    if let Some(bytes) = b256_decode(import) {
        if bytes.len() == KEY_BYTES {
            println!("Reticulum Identity imported from base256 input");
            return Ok(bytes);
        }
    }
    println!("Could not decode specified data to a valid {kind} Reticulum Identity");
    Err(R_INVALID_IDENTITY)
}

fn recall_from_disk(config_dir: &Path, hash: &AddressHash) -> Option<Identity> {
    // Read only. Saving this snapshot would replace the daemon's live table
    // with whatever was on disk at load time.
    let storage =
        reticulum::storage::FsStorage::new(config_dir.join("storage").display().to_string());
    let mut known = reticulum::storage::KnownDestinations::new();
    known.load(&storage).ok()?;
    if let Some(identity) = known.recall_no_use(hash) {
        return Some(identity);
    }
    let entries = known.entries();
    let data = reticulum::identity::recall(&entries, hash, true)?.1;
    Some(Identity::new_from_slices(
        &data.public_key[..reticulum::identity::PUBLIC_KEY_LENGTH],
        &data.public_key[reticulum::identity::PUBLIC_KEY_LENGTH..],
    ))
}

async fn recall_loaded(
    transport: &Transport,
    config_dir: &Path,
    requested: &AddressHash,
    id_destination: &AddressHash,
) -> Option<Identity> {
    if let Some(identity) = transport.recall(requested).await {
        return Some(identity);
    }
    if let Some(identity) = transport.recall(id_destination).await {
        if identity.address_hash == *requested {
            return Some(identity);
        }
    }
    recall_from_disk(config_dir, requested)
}

async fn request_identity_paths(transport: &Transport, config_dir: &Path, hashes: &[AddressHash]) {
    let attached = transport
        .iface_manager()
        .lock()
        .await
        .connected_to_shared_instance();
    if attached && request_paths_via_rpc(config_dir, hashes).await.is_ok() {
        return;
    }
    for hash in hashes {
        transport.request_path(hash, None, None).await;
    }
}

/// Ask the shared instance control channel to emit path requests.
pub(crate) async fn request_paths_via_rpc(
    config_dir: &Path,
    hashes: &[AddressHash],
) -> Result<(), String> {
    for hash in hashes {
        let request = rmpv::Value::Map(vec![
            (rmpv::Value::from("request"), rmpv::Value::from("path")),
            (
                rmpv::Value::from("destination_hash"),
                rmpv::Value::Binary(hash.as_slice().to_vec()),
            ),
        ]);
        crate::common::shared_rpc(config_dir, request).await?;
    }
    Ok(())
}

async fn retain_identity(config_dir: &Path, identity_hash: AddressHash) -> Result<(), String> {
    let request = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("identity_data"),
            rmpv::Value::from("retain"),
        ),
        (
            rmpv::Value::from("identity_hash"),
            rmpv::Value::Binary(identity_hash.as_slice().to_vec()),
        ),
    ]);
    crate::common::shared_rpc(config_dir, request)
        .await
        .map(|_| ())
}

async fn announce(
    transport: &Transport,
    resolved: &Resolved,
    aspects: &str,
) -> Result<i32, String> {
    let Some(key) = resolved.key.as_ref() else {
        println!("Could not get working identity");
        return Ok(R_NO_IDENTITY);
    };
    let parts: Vec<&str> = aspects.split('.').collect();
    if parts.len() < 2 {
        println!("Invalid destination aspects specified");
        return Ok(R_INVALID_ASPECTS);
    }
    let Some(private) = key.private_key() else {
        println!("Cannot announce this destination, since the private key is not held");
        return Ok(R_NO_PRVKEY);
    };
    let (app, rest) = split_name(aspects);
    let name = DestinationName::new(app, rest);
    let hash = name.address_hash_for(private);
    println!(
        "Announcing {aspects} destination {} for identity {}",
        prettyhexrep(hash.as_slice()),
        key.label()
    );
    let destination = transport.add_destination(private.clone(), name).await;
    transport.send_announce(&destination, None).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok(R_OK)
}

fn split_name(full_name: &str) -> (&str, &str) {
    match full_name.split_once('.') {
        Some((app, rest)) => (app, rest),
        None => (full_name, ""),
    }
}

fn destination_hash(full_name: &str, identity_hash: &[u8]) -> AddressHash {
    let name = ContentHash::generator()
        .chain_update(full_name.as_bytes())
        .finalize();
    let name_hash = &name[..NAME_HASH_LENGTH];
    let addr = ContentHash::generator()
        .chain_update(name_hash)
        .chain_update(identity_hash)
        .finalize();
    let bytes: [u8; 32] = addr.into();
    AddressHash::new_from_hash(&ContentHash::new(bytes))
}

fn print_identity_information(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    let Some(key) = resolved.key.as_ref() else {
        println!("Could not get working identity");
        return Ok(R_NO_IDENTITY);
    };
    println!("Identity Hash : {}", key.label());
    println!(
        "Public Key    : {}",
        encode_key(options, &key.public_bytes())
    );
    if key.private_key().is_some() {
        if options.print_private {
            if let Some(private) = key.private_bytes() {
                println!("Private Key   : {}", encode_key(options, &private));
            }
        } else {
            println!("Private Key   : Hidden");
        }
    }
    Ok(R_OK)
}

fn export_public(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    let Some(key) = resolved.key.as_ref() else {
        println!("Identity doesn't hold a public key, cannot export");
        return Ok(R_NO_PUBKEY);
    };
    println!(
        "Public Identity Keys  : {}",
        encode_key(options, &key.public_bytes())
    );
    Ok(R_OK)
}

fn export_private(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    let Some(private) = resolved.key.as_ref().and_then(KeyMaterial::private_bytes) else {
        println!("Identity doesn't hold a private key, cannot export");
        return Ok(R_NO_PRVKEY);
    };
    println!("Private Identity Keys : {}", encode_key(options, &private));
    Ok(R_OK)
}

fn encode_key(options: &IdOptions, bytes: &[u8]) -> String {
    if options.base64 {
        b64_encode(bytes)
    } else if options.base32 {
        b32_encode(bytes)
    } else if options.base256 {
        b256_encode(bytes)
    } else {
        hex_encode(bytes)
    }
}

fn print_hash_information(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    let Some(full_name) = options.hash.as_deref() else {
        return Ok(R_OK);
    };
    if full_name.is_empty() {
        println!("Invalid destination aspects specified");
        return Ok(R_INVALID_ASPECTS);
    }
    let identity_hash = if let Some(key) = resolved.key.as_ref() {
        key.hash().as_slice().to_vec()
    } else if let Some(hash) = resolved.requested_hash {
        hash.as_slice().to_vec()
    } else if let Some(text) = resolved.identity_arg.as_deref() {
        if text.len() != 32 {
            println!("Invalid identity hash length");
            return Ok(R_INVALID_IDENTITY);
        }
        let Some(hash) = parse_hex_hash(text) else {
            println!("Invalid identity: {text}");
            return Ok(R_INVALID_IDENTITY);
        };
        hash.as_slice().to_vec()
    } else {
        println!("Invalid identity");
        return Ok(R_INVALID_IDENTITY);
    };
    let destination = destination_hash(full_name, &identity_hash);
    println!(
        "The {full_name} destination for this Identity is {}",
        prettyhexrep(destination.as_slice())
    );
    if let Some(key) = resolved.key.as_ref() {
        let specifier = format!(
            "<{full_name}.{}:{}>",
            key.hash().to_hex_string(),
            destination.to_hex_string()
        );
        println!("The full destination specifier is {specifier}");
    }
    Ok(R_OK)
}

fn wire_format(options: &IdOptions) -> WireFormat {
    if options.base32 {
        WireFormat::Base32
    } else if options.base64 {
        WireFormat::Base64
    } else if options.base256 {
        WireFormat::Base256
    } else if options.hex {
        WireFormat::Hex
    } else {
        WireFormat::Bin
    }
}

enum WireFormat {
    Bin,
    Hex,
    Base32,
    Base64,
    Base256,
}

fn validate_paths(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    for path in &options.validate {
        let code = validate_one(options, resolved, path)?;
        if code != 0 {
            return Ok(code);
        }
    }
    Ok(R_OK)
}

fn validate_one(options: &IdOptions, resolved: &Resolved, path: &str) -> Result<i32, String> {
    let validate_path = expand_user(path);
    let name = validate_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".rsm") {
        return validate_message(options, resolved, &validate_path);
    }
    let (signature_path, file_path) = signature_and_file(&validate_path, lower.ends_with(".rsg"));
    if !file_path.is_file() {
        println!(
            "The validation target \"{}\" does not exist",
            file_path.display()
        );
        return Ok(R_NO_FILE);
    }
    if !signature_path.is_file() {
        println!("No signature file exists for \"{}\"", file_path.display());
        return Ok(R_NO_FILE);
    }
    let signature = match std::fs::read(&signature_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("Could not read rsg: {err}");
            return Ok(R_READ_ERROR);
        }
    };
    let message = match std::fs::read(&file_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("Could not read {}: {err}", file_path.display());
            return Ok(R_READ_ERROR);
        }
    };
    if signature.len() == SIG_BYTES {
        let Some(identity) = resolved.key.as_ref().map(KeyMaterial::public_identity) else {
            println!("Cannot validate legacy rsg signatures without an explicit required identity");
            return Ok(R_NO_IDENTITY);
        };
        let bytes: [u8; SIG_BYTES] = signature.as_slice().try_into().unwrap_or([0; SIG_BYTES]);
        let sig = Signature::from_bytes(&bytes);
        if identity.verify(&message, &sig).is_ok() {
            println!(
                "Signature is valid, the file {} was signed by {}",
                file_path.display(),
                prettyhexrep(identity.address_hash.as_slice())
            );
            return Ok(R_OK);
        }
        println!(
            "Invalid signature {} for file {}\nThis file was NOT signed by {}",
            signature_path.display(),
            file_path.display(),
            prettyhexrep(identity.address_hash.as_slice())
        );
        return Ok(R_INVALID_SIGNATURE);
    }
    match check_rsg(&signature, &message, resolved) {
        RsgCheck::Valid(label) => {
            println!(
                "Signature is valid, the file {} was signed by {label}",
                file_path.display()
            );
            Ok(R_OK)
        }
        RsgCheck::Invalid => {
            let extra = signer_suffix(resolved);
            println!(
                "Invalid signature {} for file {}{extra}",
                signature_path.display(),
                file_path.display()
            );
            Ok(R_INVALID_SIGNATURE)
        }
    }
}

fn signature_and_file(validate_path: &Path, is_sig: bool) -> (PathBuf, PathBuf) {
    if is_sig {
        let text = validate_path.to_string_lossy();
        let file_path = PathBuf::from(&text[..text.len().saturating_sub(4)]);
        (validate_path.to_path_buf(), file_path)
    } else {
        let mut signature = validate_path.as_os_str().to_os_string();
        signature.push(".rsg");
        (PathBuf::from(signature), validate_path.to_path_buf())
    }
}

fn signer_suffix(resolved: &Resolved) -> String {
    if let Some(key) = resolved.key.as_ref() {
        format!("\nThis file was NOT signed by {}", key.label())
    } else if let Some(hash) = resolved.requested_hash {
        format!(
            "\nThis file was NOT signed by {}",
            prettyhexrep(hash.as_slice())
        )
    } else {
        String::new()
    }
}

fn validate_message(options: &IdOptions, resolved: &Resolved, path: &Path) -> Result<i32, String> {
    if !path.is_file() {
        println!("The signature file \"{}\" does not exist", path.display());
        return Ok(R_NO_FILE);
    }
    let signature = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("Could not read rsg: {err}");
            return Ok(R_READ_ERROR);
        }
    };
    let Some(view) = unpack_rsg(&signature) else {
        println!("Error while validating {}: invalid rsg", path.display());
        return Ok(R_UNKNOWN_ERROR);
    };
    let Some(message) = view.message.clone() else {
        println!("No embedded message in {}", path.display());
        return Ok(R_INVALID_SIGNATURE);
    };
    match check_rsg(&signature, &message, resolved) {
        RsgCheck::Valid(label) => {
            if options.meta {
                println!("RSM Metadata\n============\n");
                print_meta(&view.meta, 1);
                println!("\nValidation\n==========");
            }
            let colon = if options.meta { "" } else { ":" };
            let following = if options.meta { "" } else { " following" };
            println!("\nSignature is valid, the{following} message was signed by {label}{colon}\n");
            if options.meta {
                println!("Message\n=======\n");
            }
            match String::from_utf8(message) {
                Ok(text) => println!("{text}"),
                Err(err) => {
                    println!("Error while validating {}: {err}", path.display());
                    return Ok(R_UNKNOWN_ERROR);
                }
            }
            Ok(R_OK)
        }
        RsgCheck::Invalid => {
            let extra = if resolved.key.is_some() || resolved.requested_hash.is_some() {
                let label = resolved
                    .key
                    .as_ref()
                    .map(KeyMaterial::label)
                    .unwrap_or_else(|| {
                        prettyhexrep(
                            resolved
                                .requested_hash
                                .unwrap_or_else(AddressHash::new_empty)
                                .as_slice(),
                        )
                    });
                format!("\nThe message was NOT signed by {label}")
            } else {
                String::new()
            };
            println!("Invalid signature in {}{extra}", path.display());
            Ok(R_INVALID_SIGNATURE)
        }
    }
}

enum RsgCheck {
    Valid(String),
    Invalid,
}

pub(crate) struct SignedView {
    pub(crate) hash: Vec<u8>,
    pub(crate) pubkey: Vec<u8>,
    pub(crate) message: Option<Vec<u8>>,
    pub(crate) meta: rmpv::Value,
}

fn verify_envelope(identity: &Identity, rsg: &[u8]) -> bool {
    let Ok(bytes) = <[u8; SIG_BYTES]>::try_from(&rsg[..SIG_BYTES]) else {
        return false;
    };
    let sig = Signature::from_bytes(&bytes);
    identity.verify(&rsg[SIG_BYTES..], &sig).is_ok()
}

/// `-N` leaves no loaded key. `-V` and embedded-message checks still require
/// the unresolved `-i` hash to match the embedded public key.
fn check_rsg(rsg: &[u8], message: &[u8], resolved: &Resolved) -> RsgCheck {
    // A supplied identity is the verifier. A hash only has to match the
    // embedded public key. With neither, the embedded key is enough.
    if let Some(key) = resolved.key.as_ref() {
        let Some(view) = unpack_rsg(rsg) else {
            return RsgCheck::Invalid;
        };
        if view.hash.as_slice() != sha256(message).as_slice() {
            return RsgCheck::Invalid;
        }
        if !verify_envelope(key.public_identity(), rsg) {
            return RsgCheck::Invalid;
        }
        return RsgCheck::Valid(key.label());
    }
    match verify_rsg(rsg, message, resolved.requested_hash.as_ref()) {
        Some((_, identity)) => RsgCheck::Valid(prettyhexrep(identity.address_hash.as_slice())),
        None => RsgCheck::Invalid,
    }
}

/// Verify an RSG envelope: the embedded hash matches `sha256(message)`, the
/// signature verifies under the embedded public key, and `required_signer`
/// (when given) is that signer's identity hash.
pub(crate) fn verify_rsg(
    rsg: &[u8],
    message: &[u8],
    required_signer: Option<&AddressHash>,
) -> Option<(SignedView, Identity)> {
    let view = unpack_rsg(rsg)?;
    if view.hash.as_slice() != sha256(message).as_slice() {
        return None;
    }
    let loaded = Identity::new_from_slices(
        &view.pubkey[..reticulum::identity::PUBLIC_KEY_LENGTH],
        &view.pubkey[reticulum::identity::PUBLIC_KEY_LENGTH..],
    );
    if let Some(hash) = required_signer {
        if loaded.address_hash != *hash {
            return None;
        }
    }
    if !verify_envelope(&loaded, rsg) {
        return None;
    }
    Some((view, loaded))
}

pub(crate) fn unpack_rsg(rsg: &[u8]) -> Option<SignedView> {
    if rsg.len() < SIG_BYTES + 1 {
        return None;
    }
    let envelope = &rsg[SIG_BYTES..];
    let value = rmpv::decode::read_value(&mut &envelope[..]).ok()?;
    let hashtype = map_value(&value, "hashtype")?.as_str()?;
    if hashtype != "sha256" {
        return None;
    }
    let hash = map_value(&value, "hash")?.as_slice()?.to_vec();
    let meta = map_value(&value, "meta")?.clone();
    let signer = map_value(&meta, "signer")?.as_slice()?;
    if signer.is_empty() {
        return None;
    }
    let pubkey = map_value(&meta, "pubkey")?.as_slice()?.to_vec();
    if pubkey.len() != KEY_BYTES {
        return None;
    }
    let message = map_value(&value, "message")
        .and_then(|item| item.as_slice())
        .map(|bytes| bytes.to_vec());
    Some(SignedView {
        hash,
        pubkey,
        message,
        meta,
    })
}

fn map_value<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn print_meta(value: &rmpv::Value, level: usize) {
    let Some(entries) = value.as_map() else {
        return;
    };
    for (key, entry) in entries {
        let key = key.as_str().unwrap_or("?");
        print_meta_entry(entry, key, level);
    }
}

fn print_meta_entry(entry: &rmpv::Value, key: &str, level: usize) {
    let indent = "  ".repeat(level);
    if let Some(map) = entry.as_map() {
        println!("d{indent}{key}:");
        for (child, value) in map {
            print_meta_entry(value, child.as_str().unwrap_or("?"), level + 1);
        }
        return;
    }
    let kind = if entry.is_str() {
        "s"
    } else if entry.is_bin() || entry.as_slice().is_some() {
        "b"
    } else if entry.is_array() {
        "l"
    } else if entry.is_i64() || entry.is_u64() {
        "i"
    } else if entry.is_f64() {
        "f"
    } else if entry.is_nil() {
        "N"
    } else {
        "u"
    };
    if key == "note" && entry.is_nil() {
        return;
    }
    let rendered = if let Some(bytes) = entry.as_slice() {
        hex_encode(bytes)
    } else if let Some(text) = entry.as_str() {
        text.to_string()
    } else if entry.is_nil() {
        "None".to_string()
    } else {
        format!("{entry}")
    };
    let lead = format!("{kind}{indent}{key}=");
    let width = 64;
    let mut rest = rendered.as_str();
    let first = rest.chars().take(width).collect::<String>();
    println!("{lead}{first}");
    rest = &rest[first.len()..];
    while !rest.is_empty() {
        let chunk = rest.chars().take(width).collect::<String>();
        println!("{:width$}{chunk}", "", width = lead.chars().count());
        rest = &rest[chunk.len()..];
    }
}

fn sign_paths(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    for path in &options.sign {
        let code = sign_one(options, resolved, path)?;
        if code != 0 {
            return Ok(code);
        }
    }
    Ok(R_OK)
}

fn sign_one(options: &IdOptions, resolved: &Resolved, path: &str) -> Result<i32, String> {
    let sign_path = expand_user(path);
    let mut signature_path = sign_path.clone().into_os_string();
    signature_path.push(".rsg");
    let signature_path = PathBuf::from(signature_path);
    let format = wire_format(options);
    let Some(private) = resolved.key.as_ref().and_then(KeyMaterial::private_key) else {
        println!(
            "Cannot sign \"{}\", the identity does not hold a private key",
            sign_path.display()
        );
        return Ok(R_NO_PRVKEY);
    };
    if !sign_path.is_file() {
        println!("The file \"{}\" does not exist", sign_path.display());
        return Ok(R_NO_FILE);
    }
    if matches!(format, WireFormat::Bin) && signature_path.is_file() && !options.force {
        println!(
            "The signature file \"{}\" already exists, not overwriting",
            signature_path.display()
        );
        return Ok(R_FILE_EXISTS);
    }
    let data = match std::fs::read(&sign_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("Could not sign {}: {err}", sign_path.display());
            return Ok(R_UNKNOWN_ERROR);
        }
    };
    if options.raw {
        let signature = private.sign(&data).to_bytes();
        if let Err(err) = std::fs::write(&signature_path, signature) {
            println!("Could not sign {}: {err}", sign_path.display());
            return Ok(R_UNKNOWN_ERROR);
        }
    } else {
        let rsg = pack_rsg(private, &data, false, &[]);
        match format {
            WireFormat::Bin => {
                if let Err(err) = std::fs::write(&signature_path, rsg) {
                    println!("Could not sign {}: {err}", sign_path.display());
                    return Ok(R_UNKNOWN_ERROR);
                }
            }
            _ => {
                let encoded = encode_wire(&format, &rsg);
                println!("\n{}\n", wrap_rsg(&encoded));
            }
        }
    }
    println!(
        "Signed file {} with {}",
        sign_path.display(),
        prettyhexrep(private.address_hash().as_slice())
    );
    Ok(R_OK)
}

fn sign_message(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    let format = wire_format(options);
    if matches!(format, WireFormat::Bin) && options.write.is_none() {
        println!("No write path specified");
        return Ok(R_INVALID_ARGS);
    }
    let Some(private) = resolved.key.as_ref().and_then(KeyMaterial::private_key) else {
        println!("Cannot sign, the identity does not hold a private key");
        return Ok(R_NO_PRVKEY);
    };
    let supplied = options.sign_message.clone().unwrap_or_default();
    let message = if let Some(read) = &options.read {
        if !supplied.is_empty() {
            println!(
                "Both an input file and command-line provided message was specified, aborting"
            );
            return Ok(R_INVALID_ARGS);
        }
        let path = expand_user(read);
        if !path.is_file() {
            println!("The file {} does not exist", path.display());
            return Ok(R_NO_FILE);
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                println!("Could not sign message: {err}");
                return Ok(R_UNKNOWN_ERROR);
            }
        }
    } else if supplied.is_empty() {
        match editor_content() {
            Ok(text) => text,
            Err(code) => return Ok(code),
        }
    } else {
        supplied
    };
    if message.is_empty() {
        println!("No message specified");
        return Ok(R_INVALID_ARGS);
    }
    let meta = if let Some(embed) = &options.embed_meta {
        match load_embed_meta(embed, options.meta_spec.as_deref()) {
            Ok(meta) => meta,
            Err(code) => return Ok(code),
        }
    } else {
        Vec::new()
    };
    let meta: Vec<_> = meta
        .iter()
        .map(|(key, value)| (rmpv::Value::from(key.as_str()), meta_value_to_rmpv(value)))
        .collect();
    let rsg = pack_rsg(private, message.as_bytes(), true, &meta);
    if matches!(format, WireFormat::Bin) {
        let Some(write) = options.write.as_deref() else {
            println!("No write path specified");
            return Ok(R_INVALID_ARGS);
        };
        let mut path = expand_user(write);
        if !path
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".rsm")
        {
            let mut text = path.into_os_string();
            text.push(".rsm");
            path = PathBuf::from(text);
        }
        if path.is_file() && !options.force {
            println!(
                "The signature file \"{}\" already exists, not overwriting",
                path.display()
            );
            return Ok(R_FILE_EXISTS);
        }
        if let Err(err) = std::fs::write(&path, rsg) {
            println!("Could not sign message: {err}");
            return Ok(R_UNKNOWN_ERROR);
        }
        println!(
            "Message signed with {} saved to {}",
            prettyhexrep(private.address_hash().as_slice()),
            path.display()
        );
        return Ok(R_OK);
    }
    let encoded = encode_wire(&format, &rsg);
    println!("\n{}\n", wrap_rsg(&encoded));
    println!(
        "Message signed with {}",
        prettyhexrep(private.address_hash().as_slice())
    );
    Ok(R_OK)
}

fn encode_wire(format: &WireFormat, rsg: &[u8]) -> String {
    match format {
        WireFormat::Bin => hex_encode(rsg),
        WireFormat::Hex => hex_encode(rsg),
        WireFormat::Base32 => b32_encode(rsg),
        WireFormat::Base64 => b64_encode(rsg),
        WireFormat::Base256 => b256_encode(rsg),
    }
}

/// RSG envelope: `signature ++ packb({hashtype, hash, meta{, message}})`
/// where `meta` carries signer and pubkey plus the extra `meta` pairs.
pub(crate) fn pack_rsg(
    signer: &PrivateIdentity,
    message: &[u8],
    embed: bool,
    meta: &[(rmpv::Value, rmpv::Value)],
) -> Vec<u8> {
    let mut meta_pairs = Vec::with_capacity(meta.len() + 2);
    meta_pairs.push((
        rmpv::Value::from("signer"),
        rmpv::Value::Binary(signer.address_hash().as_slice().to_vec()),
    ));
    meta_pairs.push((
        rmpv::Value::from("pubkey"),
        rmpv::Value::Binary(signer.as_identity().to_bytes().to_vec()),
    ));
    for (key, value) in meta {
        if key.as_str() == Some("signer") || key.as_str() == Some("pubkey") {
            continue;
        }
        meta_pairs.push((key.clone(), value.clone()));
    }
    let mut pairs = vec![
        (rmpv::Value::from("hashtype"), rmpv::Value::from("sha256")),
        (
            rmpv::Value::from("hash"),
            rmpv::Value::Binary(sha256(message).to_vec()),
        ),
        (rmpv::Value::from("meta"), rmpv::Value::Map(meta_pairs)),
    ];
    if embed {
        pairs.push((
            rmpv::Value::from("message"),
            rmpv::Value::Binary(message.to_vec()),
        ));
    }
    let envelope = crate::common::rmpv_to_bytes(&rmpv::Value::Map(pairs));
    let signature = signer.sign(&envelope).to_bytes();
    let mut out = Vec::with_capacity(SIG_BYTES + envelope.len());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&envelope);
    out
}

fn meta_value_to_rmpv(value: &MetaValue) -> rmpv::Value {
    match value {
        MetaValue::Null => rmpv::Value::Nil,
        MetaValue::Bool(value) => rmpv::Value::Boolean(*value),
        MetaValue::Int(value) => rmpv::Value::from(*value),
        MetaValue::Float(value) => rmpv::Value::F64(*value),
        MetaValue::Str(value) => rmpv::Value::from(value.as_str()),
        MetaValue::List(items) => {
            rmpv::Value::Array(items.iter().map(meta_value_to_rmpv).collect())
        }
        MetaValue::Map(entries) => rmpv::Value::Map(
            entries
                .iter()
                .map(|(key, value)| (rmpv::Value::from(key.as_str()), meta_value_to_rmpv(value)))
                .collect(),
        ),
    }
}

const RSG_HEADER: &str = "#### Start of rsg data ";
const RSG_FOOTER: &str = " End of rsg data ####";
const RSG_WIDTH: usize = 64;

fn wrap_rsg(rsg: &str) -> String {
    let header = format!("{RSG_HEADER}{}", "#".repeat(RSG_WIDTH - RSG_HEADER.len()));
    let footer = format!("{}{RSG_FOOTER}", "#".repeat(RSG_WIDTH - RSG_FOOTER.len()));
    let mut wrapped = String::new();
    wrapped.push_str(&header);
    wrapped.push('\n');
    let chars: Vec<char> = rsg.chars().collect();
    for chunk in chars.chunks(RSG_WIDTH) {
        let mut line: String = chunk.iter().collect();
        if chunk.len() < RSG_WIDTH {
            line.push_str(&"=".repeat(RSG_WIDTH - chunk.len()));
        }
        wrapped.push_str(&line);
        wrapped.push('\n');
    }
    wrapped.push_str(&footer);
    wrapped
}

fn encrypt_paths(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    for path in &options.encrypt {
        let code = encrypt_one(options, resolved, path)?;
        if code != 0 {
            return Ok(code);
        }
    }
    Ok(R_OK)
}

fn encrypt_one(options: &IdOptions, resolved: &Resolved, path: &str) -> Result<i32, String> {
    let encrypt_path = expand_user(path);
    let output_path = match options.write.as_deref() {
        Some(write) => expand_user(write),
        None => {
            let mut out = encrypt_path.clone().into_os_string();
            out.push(".rfe");
            PathBuf::from(out)
        }
    };
    let Some(key) = resolved.key.as_ref() else {
        println!(
            "Cannot encrypt \"{}\", no identity specified",
            encrypt_path.display()
        );
        return Ok(R_NO_IDENTITY);
    };
    if !encrypt_path.is_file() {
        println!("The file \"{}\" does not exist", encrypt_path.display());
        return Ok(R_NO_FILE);
    }
    if output_path.is_file() && !options.force {
        println!(
            "The encryption output file \"{}\" already exists, not overwriting",
            output_path.display()
        );
        return Ok(R_FILE_EXISTS);
    }
    let mut input = match File::open(&encrypt_path) {
        Ok(file) => file,
        Err(err) => {
            println!(
                "\nError reading {} for encryption: {err}",
                encrypt_path.display()
            );
            return Ok(R_WRITE_ERROR);
        }
    };
    let mut output = match File::create(&output_path) {
        Ok(file) => file,
        Err(err) => {
            println!(
                "\nError writing encrypted output to {}: {err}",
                output_path.display()
            );
            return Ok(R_WRITE_ERROR);
        }
    };
    let mut wrote: u64 = 0;
    loop {
        let mut chunk = vec![0u8; ENC_CHUNK];
        let read = match read_chunk(&mut input, &mut chunk) {
            Ok(read) => read,
            Err(err) => {
                println!(
                    "\nError reading {} for encryption: {err}",
                    encrypt_path.display()
                );
                return Ok(R_WRITE_ERROR);
            }
        };
        if read == 0 {
            print!(
                "\rWrote {} to {}   ",
                prettysize(wrote as f64),
                output_path.display()
            );
            let _ = std::io::stdout().flush();
            break;
        }
        let encrypted = match encrypt_chunk(key.public_identity(), &chunk[..read]) {
            Ok(bytes) => bytes,
            Err(err) => {
                println!(
                    "\nError writing encrypted output to {}: {err}",
                    output_path.display()
                );
                return Ok(R_WRITE_ERROR);
            }
        };
        if let Err(err) = output.write_all(&encrypted) {
            println!(
                "\nError writing encrypted output to {}: {err}",
                output_path.display()
            );
            return Ok(R_WRITE_ERROR);
        }
        wrote += encrypted.len() as u64;
        print!(
            "\rWrote {} to {}   ",
            prettysize(wrote as f64),
            output_path.display()
        );
        let _ = std::io::stdout().flush();
    }
    println!(
        "\nFile {} encrypted for {} to {}",
        encrypt_path.display(),
        key.label(),
        output_path.display()
    );
    Ok(R_OK)
}

fn decrypt_paths(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    for path in &options.decrypt {
        let code = decrypt_one(options, resolved, path)?;
        if code != 0 {
            return Ok(code);
        }
    }
    Ok(R_OK)
}

fn decrypt_one(options: &IdOptions, resolved: &Resolved, path: &str) -> Result<i32, String> {
    let rfe_path = expand_user(path);
    if !rfe_path.to_string_lossy().ends_with(".rfe") {
        println!(
            "The file {} does not appear to be a Reticulum encrypted file",
            rfe_path.display()
        );
        return Ok(R_INVALID_FILE);
    }
    let output_path = match options.write.as_deref() {
        Some(write) => expand_user(write),
        None => {
            let text = rfe_path.to_string_lossy();
            PathBuf::from(&text[..text.len() - 4])
        }
    };
    if output_path.as_os_str().is_empty() {
        println!("Invalid output filename");
        return Ok(R_INVALID_FILE);
    }
    let Some(private) = resolved.key.as_ref().and_then(KeyMaterial::private_key) else {
        if resolved.key.is_none() {
            println!(
                "Cannot decrypt \"{}\", no identity specified",
                rfe_path.display()
            );
            return Ok(R_NO_IDENTITY);
        }
        println!(
            "Cannot decrypt \"{}\", the identity does not hold a private key",
            rfe_path.display()
        );
        return Ok(R_NO_PRVKEY);
    };
    if !rfe_path.is_file() {
        println!("The file \"{}\" does not exist", rfe_path.display());
        return Ok(R_NO_FILE);
    }
    if output_path.is_file() && !options.force {
        println!(
            "The decryption output file \"{}\" already exists, not overwriting",
            output_path.display()
        );
        return Ok(R_FILE_EXISTS);
    }
    let mut input = match File::open(&rfe_path) {
        Ok(file) => file,
        Err(err) => {
            println!(
                "\nError reading {} for decryption: {err}",
                rfe_path.display()
            );
            return Ok(R_WRITE_ERROR);
        }
    };
    let mut output = match File::create(&output_path) {
        Ok(file) => file,
        Err(err) => {
            println!(
                "\nError writing decrypted output to {}: {err}",
                output_path.display()
            );
            return Ok(R_WRITE_ERROR);
        }
    };
    let mut wrote: u64 = 0;
    loop {
        let mut chunk = vec![0u8; DEC_CHUNK];
        let read = match read_chunk(&mut input, &mut chunk) {
            Ok(read) => read,
            Err(err) => {
                println!(
                    "\nError reading {} for decryption: {err}",
                    rfe_path.display()
                );
                return Ok(R_WRITE_ERROR);
            }
        };
        if read == 0 {
            print!(
                "\rWrote {} to {}   ",
                prettysize(wrote as f64),
                output_path.display()
            );
            let _ = std::io::stdout().flush();
            break;
        }
        match decrypt_chunk(private, &chunk[..read]) {
            Ok(plain) => {
                if let Err(err) = output.write_all(&plain) {
                    println!(
                        "\nError writing decrypted output to {}: {err}",
                        output_path.display()
                    );
                    return Ok(R_WRITE_ERROR);
                }
                wrote += plain.len() as u64;
                print!(
                    "\rWrote {} to {}   ",
                    prettysize(wrote as f64),
                    output_path.display()
                );
                let _ = std::io::stdout().flush();
            }
            Err(_) => {
                println!("The provided identity could not decrypt the file");
                return Ok(R_DECRYPT_FAILED);
            }
        }
    }
    println!(
        "\nFile {} decrypted to {}",
        rfe_path.display(),
        output_path.display()
    );
    Ok(R_OK)
}

/// Fill `buf` until it is full or the reader reaches EOF.
///
/// One `Read::read` may return early. A Fernet record is one full chunk,
/// so a short read must not be encrypted or decrypted on its own.
fn read_chunk(input: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn encrypt_chunk(identity: &Identity, chunk: &[u8]) -> Result<Vec<u8>, String> {
    // PKCS#7 adds a full block when the plaintext is block-aligned. The
    // Fernet size check uses div_ceil and misses that block, so the buffer
    // has to be one block larger than that check.
    let blocks = chunk.len() / 16 + 1;
    let mut buf = vec![0u8; 32 + 16 + blocks * 16 + 32];
    let out = identity
        .encrypt(OsRng, chunk, None, &mut buf)
        .map_err(|err| format!("{err:?}"))?;
    Ok(out.to_vec())
}

fn decrypt_chunk(identity: &PrivateIdentity, chunk: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; chunk.len()];
    let out = identity
        .decrypt(chunk, &[], &mut buf)
        .map_err(|err| format!("{err:?}"))?;
    Ok(out.to_vec())
}

fn write_identity(options: &IdOptions, resolved: &Resolved) -> Result<i32, String> {
    let Some(write) = options.write.as_deref() else {
        return Ok(R_OK);
    };
    let mut path = expand_user(write);
    let Some(key) = resolved.key.as_ref() else {
        println!("Identity holds neither a public nor private key");
        return Ok(R_NO_KEYS);
    };
    if key.private_key().is_some() && options.export_prv {
        if path.is_file() && !options.force {
            println!("File {} already exists, not overwriting", path.display());
            return Ok(R_FILE_EXISTS);
        }
        let Some(bytes) = key.private_bytes() else {
            println!("Identity holds neither a public nor private key");
            return Ok(R_NO_KEYS);
        };
        if let Err(err) = write_private_bytes(&path, &bytes) {
            println!("Error while writing imported identity to file: {err}");
            return Ok(R_WRITE_ERROR);
        }
        println!("Wrote private identity to {}", path.display());
        return Ok(R_OK);
    }
    if !path
        .to_string_lossy()
        .to_ascii_lowercase()
        .ends_with(".pub")
    {
        let mut text = path.into_os_string();
        text.push(".pub");
        path = PathBuf::from(text);
    }
    if path.is_file() && !options.force {
        println!("File {} already exists, not overwriting", path.display());
        return Ok(R_FILE_EXISTS);
    }
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            println!("Error while writing imported identity to file: {err}");
            return Ok(R_WRITE_ERROR);
        }
    }
    if let Err(err) = std::fs::write(&path, key.public_bytes()) {
        println!("Error while writing imported identity to file: {err}");
        return Ok(R_WRITE_ERROR);
    }
    println!("Wrote public identity to {}", path.display());
    Ok(R_OK)
}

fn write_private_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

fn editor_content() -> Result<String, i32> {
    let editor = std::env::var("EDITOR").unwrap_or_default();
    let editor = if editor.is_empty() {
        ["nano", "vim", "vi"]
            .into_iter()
            .find(|name| {
                std::process::Command::new("which")
                    .arg(name)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false)
            })
            .unwrap_or("")
            .to_string()
    } else {
        editor
    };
    if editor.is_empty() {
        println!("Could not launch editor");
        return Err(R_READ_ERROR);
    }
    let path = std::env::temp_dir().join(format!("rnid-msg-{}", std::process::id()));
    if std::fs::write(&path, "").is_err() {
        println!("Could not get content from editor: could not create temporary file");
        return Err(R_READ_ERROR);
    }
    let status = std::process::Command::new(&editor).arg(&path).status();
    let content = std::fs::read_to_string(&path);
    let _ = std::fs::remove_file(&path);
    match status {
        Ok(status) if status.success() => match content {
            Ok(text) => Ok(text),
            Err(err) => {
                println!("Could not get content from editor: {err}");
                Err(R_READ_ERROR)
            }
        },
        Ok(status) => {
            println!(
                "Editor exited with error code {}",
                status.code().unwrap_or(1)
            );
            Err(R_READ_ERROR)
        }
        Err(err) => {
            println!("Could not get content from editor: {err}");
            Err(R_READ_ERROR)
        }
    }
}

fn load_embed_meta(path: &str, spec: Option<&str>) -> Result<Vec<(String, MetaValue)>, i32> {
    if path.is_empty() {
        println!("Metadata file  does not exist");
        return Err(R_NO_FILE);
    }
    let meta_path = expand_user(path);
    if !meta_path.is_file() {
        println!("Metadata file {} does not exist", meta_path.display());
        return Err(R_NO_FILE);
    }
    let spec_path = match spec {
        Some(spec) => Some(expand_user(spec)),
        None => {
            let mut guess = meta_path.clone().into_os_string();
            guess.push(".spec");
            let guess = PathBuf::from(guess);
            if guess.is_file() {
                Some(guess)
            } else {
                None
            }
        }
    };
    let spec_path = spec_path.filter(|path| path.is_file());
    let spec_info = spec_path
        .as_ref()
        .map(|path| format!(" using spec from {}", path.display()))
        .unwrap_or_default();
    println!("Embedding metadata from {}{spec_info}", meta_path.display());
    let text = match std::fs::read_to_string(&meta_path) {
        Ok(text) => text,
        Err(err) => {
            println!(
                "Could not load metadata from {}: {err}",
                meta_path.display()
            );
            return Err(R_UNKNOWN_ERROR);
        }
    };
    let mut parsed = match parse_config(&text) {
        Ok(parsed) => parsed,
        Err(err) => {
            println!(
                "Could not load metadata from {}: {err}",
                meta_path.display()
            );
            return Err(R_UNKNOWN_ERROR);
        }
    };
    if let Some(spec_path) = spec_path {
        let spec_text = match std::fs::read_to_string(&spec_path) {
            Ok(text) => text,
            Err(err) => {
                println!(
                    "Could not load metadata from {}: {err}",
                    meta_path.display()
                );
                return Err(R_UNKNOWN_ERROR);
            }
        };
        let spec = match parse_config(&spec_text) {
            Ok(spec) => spec,
            Err(err) => {
                println!(
                    "Could not load metadata from {}: {err}",
                    meta_path.display()
                );
                return Err(R_UNKNOWN_ERROR);
            }
        };
        if let Err(err) = apply_spec(&mut parsed, &spec) {
            println!(
                "Could not load metadata from {}: {err}",
                meta_path.display()
            );
            return Err(R_UNKNOWN_ERROR);
        }
    }
    Ok(parsed)
}

#[derive(Clone, Debug, PartialEq)]
enum MetaValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<MetaValue>),
    Map(Vec<(String, MetaValue)>),
}

type SectionFrame = (usize, String, Vec<(String, MetaValue)>);

fn parse_config(text: &str) -> Result<Vec<(String, MetaValue)>, String> {
    let mut root = Vec::new();
    let mut stack: Vec<SectionFrame> = Vec::new();
    for raw in text.lines() {
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let depth = line.chars().take_while(|ch| *ch == '[').count();
            let end = line.chars().rev().take_while(|ch| *ch == ']').count();
            if depth == 0 || depth != end || line.len() <= depth * 2 {
                return Err("Metadata did not pass spec validation".into());
            }
            let name = line[depth..line.len() - depth].trim().to_string();
            while stack.last().is_some_and(|frame| frame.0 >= depth) {
                let frame = stack.pop().expect("frame");
                push_section(&mut root, &mut stack, frame);
            }
            stack.push((depth, name, Vec::new()));
            continue;
        }
        let Some((key, value)) = split_assign(&line) else {
            return Err("Metadata did not pass spec validation".into());
        };
        let parsed = parse_config_value(value.trim());
        if let Some(frame) = stack.last_mut() {
            frame.2.push((key, parsed));
        } else {
            root.push((key, parsed));
        }
    }
    while let Some(frame) = stack.pop() {
        push_section(&mut root, &mut stack, frame);
    }
    Ok(root)
}

fn push_section(
    root: &mut Vec<(String, MetaValue)>,
    stack: &mut [SectionFrame],
    frame: SectionFrame,
) {
    let section = (frame.1, MetaValue::Map(frame.2));
    if let Some(parent) = stack.last_mut() {
        parent.2.push(section);
    } else {
        root.push(section);
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }
        if ch == '#' || ch == ';' {
            return &line[..index];
        }
    }
    line
}

fn split_assign(line: &str) -> Option<(String, &str)> {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }
        if ch == '=' {
            return Some((line[..index].trim().to_string(), &line[index + 1..]));
        }
    }
    None
}

fn parse_config_value(value: &str) -> MetaValue {
    if split_list(value).len() > 1 || (value.contains(',') && !is_quoted(value)) {
        MetaValue::List(
            split_list(value)
                .into_iter()
                .map(|item| MetaValue::Str(unquote(item.trim())))
                .collect(),
        )
    } else {
        MetaValue::Str(unquote(value.trim()))
    }
}

fn is_quoted(value: &str) -> bool {
    let value = value.trim();
    (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
        || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
}

fn split_list(value: &str) -> Vec<&str> {
    if is_quoted(value.trim()) {
        return vec![value];
    }
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    for (index, ch) in value.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }
        if ch == ',' {
            parts.push(&value[start..index]);
            start = index + ch.len_utf8();
        }
    }
    parts.push(&value[start..]);
    if parts.len() == 1 {
        return parts;
    }
    parts
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if is_quoted(value) {
        let inner = &value[1..value.len() - 1];
        return inner
            .replace("\\n", "\n")
            .replace("\\\"", "\"")
            .replace("\\'", "'");
    }
    value.to_string()
}

fn apply_spec(
    data: &mut Vec<(String, MetaValue)>,
    spec: &[(String, MetaValue)],
) -> Result<(), String> {
    for (key, rule) in spec {
        match rule {
            MetaValue::Map(nested) => {
                let entry = data.iter_mut().find(|(name, _)| name == key);
                if let Some((_, MetaValue::Map(child))) = entry {
                    apply_spec(child, nested)?;
                } else if entry.is_none() {
                    let mut child = Vec::new();
                    apply_spec(&mut child, nested)?;
                    data.push((key.clone(), MetaValue::Map(child)));
                } else {
                    return Err("Metadata did not pass spec validation".into());
                }
            }
            MetaValue::Str(text) => {
                let rule = parse_rule(text)?;
                if let Some((_, value)) = data.iter_mut().find(|(name, _)| name == key) {
                    *value = coerce(value, &rule)?;
                } else if let Some(default) = rule.default {
                    data.push((key.clone(), default));
                } else {
                    return Err("Metadata did not pass spec validation".into());
                }
            }
            _ => return Err("Metadata did not pass spec validation".into()),
        }
    }
    Ok(())
}

struct Rule {
    kind: RuleKind,
    default: Option<MetaValue>,
    min: Option<f64>,
    max: Option<f64>,
}

enum RuleKind {
    String,
    Integer,
    Float,
    Boolean,
    StringList,
}

fn parse_rule(text: &str) -> Result<Rule, String> {
    let (name, args) = text
        .find('(')
        .map(|index| {
            (
                text[..index].trim(),
                Some(&text[index + 1..text.len().saturating_sub(1)]),
            )
        })
        .unwrap_or((text.trim(), None));
    let kind = match name {
        "string" => RuleKind::String,
        "integer" => RuleKind::Integer,
        "float" => RuleKind::Float,
        "boolean" => RuleKind::Boolean,
        "string_list" => RuleKind::StringList,
        _ => return Err("Metadata did not pass spec validation".into()),
    };
    let mut rule = Rule {
        kind,
        default: None,
        min: None,
        max: None,
    };
    if let Some(args) = args {
        for part in split_list(args) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            match key.trim() {
                "default" => rule.default = Some(parse_default(&rule.kind, &value)),
                "min" => rule.min = value.parse().ok(),
                "max" => rule.max = value.parse().ok(),
                _ => {}
            }
        }
    }
    Ok(rule)
}

fn parse_default(kind: &RuleKind, value: &str) -> MetaValue {
    if value == "None" {
        return MetaValue::Null;
    }
    match kind {
        RuleKind::Integer => value
            .parse::<i64>()
            .map(MetaValue::Int)
            .unwrap_or(MetaValue::Str(value.to_string())),
        RuleKind::Float => value
            .parse::<f64>()
            .map(MetaValue::Float)
            .unwrap_or(MetaValue::Str(value.to_string())),
        RuleKind::Boolean => parse_bool(value)
            .map(MetaValue::Bool)
            .unwrap_or(MetaValue::Str(value.to_string())),
        RuleKind::String | RuleKind::StringList => MetaValue::Str(value.to_string()),
    }
}

fn coerce(value: &MetaValue, rule: &Rule) -> Result<MetaValue, String> {
    let fail = || Err("Metadata did not pass spec validation".to_string());
    if matches!(value, MetaValue::Null) {
        return Ok(MetaValue::Null);
    }
    match rule.kind {
        RuleKind::String => match value {
            MetaValue::Str(text) => Ok(MetaValue::Str(text.clone())),
            _ => fail(),
        },
        RuleKind::Integer => {
            let number = match value {
                MetaValue::Int(number) => *number,
                MetaValue::Str(text) => match text.parse::<i64>() {
                    Ok(number) => number,
                    Err(_) => return fail(),
                },
                _ => return fail(),
            };
            if rule.min.is_some_and(|min| (number as f64) < min)
                || rule.max.is_some_and(|max| (number as f64) > max)
            {
                return fail();
            }
            Ok(MetaValue::Int(number))
        }
        RuleKind::Float => {
            let number = match value {
                MetaValue::Float(number) => *number,
                MetaValue::Int(number) => *number as f64,
                MetaValue::Str(text) => match text.parse::<f64>() {
                    Ok(number) => number,
                    Err(_) => return fail(),
                },
                _ => return fail(),
            };
            if rule.min.is_some_and(|min| number < min) || rule.max.is_some_and(|max| number > max)
            {
                return fail();
            }
            Ok(MetaValue::Float(number))
        }
        RuleKind::Boolean => {
            let flag = match value {
                MetaValue::Bool(flag) => *flag,
                MetaValue::Str(text) => match parse_bool(text) {
                    Some(flag) => flag,
                    None => return fail(),
                },
                _ => return fail(),
            };
            Ok(MetaValue::Bool(flag))
        }
        RuleKind::StringList => match value {
            MetaValue::List(items) => {
                let mut out = Vec::new();
                for item in items {
                    match item {
                        MetaValue::Str(text) => out.push(MetaValue::Str(text.clone())),
                        _ => return fail(),
                    }
                }
                Ok(MetaValue::List(out))
            }
            _ => fail(),
        },
    }
}

fn parse_bool(text: &str) -> Option<bool> {
    match text.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn prettysize(mut num: f64) -> String {
    const UNITS: [&str; 8] = ["", "K", "M", "G", "T", "P", "E", "Z"];
    for unit in UNITS {
        if num.abs() < 1000.0 {
            if unit.is_empty() {
                return format!("{num:.0} B");
            }
            return format!("{num:.2} {unit}B");
        }
        num /= 1000.0;
    }
    format!("{num:.2}YB")
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ContentHash::generator().chain_update(data).finalize();
    digest.into()
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hex = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(hex, 16).ok()?);
    }
    Some(out)
}

fn parse_hex_hash(text: &str) -> Option<AddressHash> {
    let bytes = decode_hex(text)?;
    AddressHash::new_from_raw_slice(&bytes)
}

pub(crate) fn expand_user(path: &str) -> PathBuf {
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for byte in data {
        buffer = (buffer << 8) | u64::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(B32_ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32_ALPHABET[index] as char);
    }
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}

fn b32_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_end_matches('=').as_bytes();
    if text.is_empty() {
        return Some(Vec::new());
    }
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for byte in text {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let n = (u32::from(data[index]) << 16)
            | (u32::from(data[index + 1]) << 8)
            | u32::from(data[index + 2]);
        out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 6) & 63) as usize] as char);
        out.push(B64_ALPHABET[(n & 63) as usize] as char);
        index += 3;
    }
    if index < data.len() {
        let remain = data.len() - index;
        let mut n = u32::from(data[index]) << 16;
        if remain == 2 {
            n |= u32::from(data[index + 1]) << 8;
        }
        out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
        if remain == 2 {
            out.push(B64_ALPHABET[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_end_matches('=').as_bytes();
    if text.is_empty() {
        return Some(Vec::new());
    }
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for byte in text {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u64::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

const B256: [&str; 256] = [
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s",
    "t", "u", "v", "x", "y", "z", "æ", "ø", "0", "1", "2", "3", "4", "A", "B", "C", "D", "E", "F",
    "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "W", "X", "Y", "Z",
    "Æ", "Ø", "5", "6", "7", "8", "9", "α", "β", "γ", "δ", "ε", "ζ", "η", "θ", "ι", "κ", "λ", "μ",
    "ν", "ξ", "π", "ρ", "σ", "τ", "φ", "χ", "ψ", "ω", "Γ", "Δ", "Θ", "Λ", "Ξ", "Π", "Σ", "Φ", "Ψ",
    "Ω", "Б", "Д", "Ж", "З", "И", "Л", "П", "Ц", "Ч", "Ш", "Щ", "Ъ", "Ы", "Э", "Ю", "Я", "б", "д",
    "ж", "з", "и", "л", "п", "ц", "ч", "ш", "щ", "ъ", "ы", "э", "ю", "я", "Ա", "Բ", "Գ", "Դ", "Ե",
    "Զ", "Է", "Ը", "Թ", "Ժ", "Ի", "Խ", "Ծ", "Կ", "Հ", "Ձ", "Ղ", "Ճ", "Մ", "Յ", "Ն", "Շ", "Ո", "Չ",
    "Պ", "Ջ", "Վ", "Ր", "Ց", "Ւ", "Ք", "Ֆ", "ᚠ", "ᚢ", "ᚦ", "ᚱ", "ᚹ", "ᚺ", "ᚾ", "ᛈ", "ᛇ", "ᛉ", "ᛊ",
    "ᛏ", "ᛒ", "ᛖ", "ᛗ", "ᛟ", "ｲ", "ｳ", "ｵ", "ｶ", "ｷ", "ｹ", "ｻ", "ｼ", "ｽ", "ｾ", "ﾀ", "ﾁ", "ﾃ", "ﾄ",
    "ﾅ", "ﾇ", "ﾈ", "ﾋ", "ﾌ", "ﾍ", "ﾎ", "ﾏ", "ﾐ", "ﾑ", "ﾒ", "ﾓ", "ﾔ", "ﾗ", "ﾘ", "ﾙ", "ﾚ", "ﾜ", "𐑐",
    "𐑑", "𐑒", "𐑔", "𐑕", "𐑗", "𐑙", "𐑳", "𐑶", "𐑸", "𐑹", "𐑺", "𐑻", "𐑽", "𐑾", "𐑿", "᱑", "᱕", "᱘", "᱙",
    "ᱚ", "ᱝ", "ᱟ", "ᱣ", "ᱦ", "ᱨ", "ᱬ", "ᱭ", "ᱰ", "ᱳ", "ᱶ", "ᱷ", "𐌳", "𐌸", "𐌾", "𐐀", "𐐁", "𐐂", "𐐆",
    "𐐇", "𐐈", "𐐉", "𐐊", "𐐋", "𐐌", "𐐍", "𐐎", "𐐏",
];

fn b256_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for byte in data {
        out.push_str(B256[usize::from(*byte)]);
    }
    out
}

fn b256_decode(text: &str) -> Option<Vec<u8>> {
    let mut map = std::collections::HashMap::<char, u8>::new();
    for (index, symbol) in B256.iter().enumerate() {
        let mut chars = symbol.chars();
        let ch = chars.next()?;
        if chars.next().is_some() {
            return None;
        }
        map.entry(ch).or_insert(index as u8);
    }
    text.chars().map(|ch| map.get(&ch).copied()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn generate_and_render() {
        let info = run(IdOptions::default()).expect("run");
        assert_eq!(info, 0);
    }

    #[test]
    fn private_key_hidden_in_public_mode() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let info = info_for_private(
            &identity,
            &IdOptions {
                public: true,
                ..Default::default()
            },
        );
        assert!(info.private_key.is_none());
        let full = info_for_private(&identity, &IdOptions::default());
        assert!(full.private_key.is_some());
        assert_eq!(full.private_key.unwrap().len(), 128);
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(b32_encode(b"foo"), "MZXW6===");
        assert_eq!(b32_encode(b"foobar"), "MZXW6YTBOI======");
        assert_eq!(b32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(b32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    #[test]
    fn base64_urlsafe_matches_padded_alphabet() {
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(b64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(b64_decode("Zg==").unwrap(), b"f");
    }

    #[test]
    fn base256_roundtrip_covers_every_byte() {
        let data: Vec<u8> = (0u16..256).map(|byte| byte as u8).collect();
        let encoded = b256_encode(&data);
        assert_eq!(encoded.chars().count(), 256);
        assert_eq!(b256_decode(&encoded).unwrap(), data);
        assert_eq!(b256_encode(&[0, 1, 2]), "abc");
    }

    #[test]
    fn sign_validate_checks_signature_bytes() {
        let dir = std::env::temp_dir().join(format!("rnid-sig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let id_path = dir.join("identity");
        std::fs::write(&id_path, identity.to_bytes()).unwrap();
        let file = dir.join("note.txt");
        std::fs::write(&file, b"signed-bytes").unwrap();
        let code = run(IdOptions {
            identity: Some(id_path.display().to_string()),
            sign: vec![file.display().to_string()],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(code, 0);
        let rsg = std::fs::read(dir.join("note.txt.rsg")).unwrap();
        assert!(rsg.len() > SIG_BYTES);
        let sig = Signature::from_bytes(&<[u8; SIG_BYTES]>::try_from(&rsg[..SIG_BYTES]).unwrap());
        assert!(identity
            .as_identity()
            .verify(&rsg[SIG_BYTES..], &sig)
            .is_ok());
        let view = unpack_rsg(&rsg).unwrap();
        assert_eq!(view.hash, sha256(b"signed-bytes"));
        let code = run(IdOptions {
            identity: Some(id_path.display().to_string()),
            validate: vec![file.display().to_string()],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(code, 0);
        std::fs::write(&file, b"tampered-bytes").unwrap();
        let code = run(IdOptions {
            identity: Some(id_path.display().to_string()),
            validate: vec![file.display().to_string()],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(code, R_INVALID_SIGNATURE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn embedded_message_and_metadata_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rnid-rsm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let id_path = dir.join("identity");
        std::fs::write(&id_path, identity.to_bytes()).unwrap();
        let meta = dir.join("meta.cfg");
        std::fs::write(&meta, "name = demo\nparts = a, b\n").unwrap();
        let spec = dir.join("meta.cfg.spec");
        std::fs::write(&spec, "name = string\ncount = integer(default=4)\n").unwrap();
        let code = run(IdOptions {
            identity: Some(id_path.display().to_string()),
            sign_message: Some("hello embedded".into()),
            embed_meta: Some(meta.display().to_string()),
            write: Some(dir.join("out").display().to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(code, 0);
        let rsm = std::fs::read(dir.join("out.rsm")).unwrap();
        let view = unpack_rsg(&rsm).unwrap();
        assert_eq!(view.message.unwrap(), b"hello embedded");
        let count = map_value(&view.meta, "count").and_then(|value| value.as_i64());
        assert_eq!(count, Some(4));
        let code = run(IdOptions {
            identity: Some(id_path.display().to_string()),
            validate: vec![dir.join("out.rsm").display().to_string()],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(code, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_includes_block_aligned_plaintext() {
        let dir = std::env::temp_dir().join(format!("rnid-rfe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let id_path = dir.join("identity");
        std::fs::write(&id_path, identity.to_bytes()).unwrap();
        for (name, bytes) in [("short", &b"hi"[..]), ("aligned", &[0u8; 32][..])] {
            let plain = dir.join(name);
            std::fs::write(&plain, bytes).unwrap();
            let code = run(IdOptions {
                identity: Some(id_path.display().to_string()),
                encrypt: vec![plain.display().to_string()],
                ..Default::default()
            })
            .unwrap();
            assert_eq!(code, 0);
            let enc = dir.join(format!("{name}.rfe"));
            assert!(enc.is_file());
            let out = dir.join(format!("{name}.out"));
            let code = run(IdOptions {
                identity: Some(id_path.display().to_string()),
                decrypt: vec![enc.display().to_string()],
                write: Some(out.display().to_string()),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(code, 0);
            assert_eq!(std::fs::read(out).unwrap(), bytes);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn path_request_rpc_sends_destination_hash() {
        let dir = std::env::temp_dir().join(format!(
            "rnid-rpc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let key_hex = "00112233445566778899aabbccddeeff";
        std::fs::write(
            dir.join("config.toml"),
            format!(
                "[reticulum]\nshare_instance = true\nshared_instance_type = \"tcp\"\ninstance_control_port = {port}\nrpc_key = \"{key_hex}\"\n"
            ),
        )
        .unwrap();
        let authkey = crate::rpc::decode_hex_key(key_hex).unwrap();
        let first = AddressHash::new_from_raw_slice(&[0xab; 16]).unwrap();
        let second = AddressHash::new_from_raw_slice(&[0xcd; 16]).unwrap();
        let expected = vec![first, second];
        let server_key = authkey.clone();
        let received = tokio::spawn(async move {
            let mut got = Vec::new();
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                crate::rpc::server_handshake(&mut sock, &server_key)
                    .await
                    .unwrap();
                let frame = crate::rpc::recv_bytes(&mut sock, None)
                    .await
                    .unwrap()
                    .unwrap();
                let value = rmpv::decode::read_value(&mut frame.as_slice()).unwrap();
                got.push(value);
                let mut packed = Vec::new();
                rmpv::encode::write_value(&mut packed, &rmpv::Value::Boolean(true)).unwrap();
                crate::rpc::send_bytes(&mut sock, &packed).await.unwrap();
            }
            got
        });
        request_paths_via_rpc(&dir, &expected).await.unwrap();
        let got = received.await.unwrap();
        assert_eq!(got.len(), 2);
        for (value, hash) in got.iter().zip(expected.iter()) {
            let request = value
                .as_map()
                .unwrap()
                .iter()
                .find(|(key, _)| key.as_str() == Some("request"))
                .unwrap()
                .1
                .as_str();
            assert_eq!(request, Some("path"));
            let destination = value
                .as_map()
                .unwrap()
                .iter()
                .find(|(key, _)| key.as_str() == Some("destination_hash"))
                .unwrap()
                .1
                .as_slice()
                .unwrap();
            assert_eq!(destination, hash.as_slice());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_cache_hash_still_constrains_validation() {
        let dir = std::env::temp_dir().join(format!("rnid-nocache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let other = PrivateIdentity::new_from_rand(OsRng);
        let id_path = dir.join("identity");
        std::fs::write(&id_path, identity.to_bytes()).unwrap();
        let file = dir.join("note.txt");
        std::fs::write(&file, b"payload").unwrap();
        assert_eq!(
            run(IdOptions {
                identity: Some(id_path.display().to_string()),
                sign: vec![file.display().to_string()],
                ..Default::default()
            })
            .unwrap(),
            0
        );
        let hash = identity.address_hash().to_hex_string();
        assert_eq!(
            run(IdOptions {
                identity: Some(hash.clone()),
                no_cache: true,
                validate: vec![file.display().to_string()],
                config: Some(dir.clone()),
                ..Default::default()
            })
            .unwrap(),
            0
        );
        assert_eq!(
            run(IdOptions {
                identity: Some(other.address_hash().to_hex_string()),
                no_cache: true,
                validate: vec![file.display().to_string()],
                config: Some(dir.clone()),
                ..Default::default()
            })
            .unwrap(),
            R_INVALID_SIGNATURE
        );
        assert_eq!(
            run(IdOptions {
                identity: Some("zz".into()),
                no_cache: true,
                validate: vec![file.display().to_string()],
                ..Default::default()
            })
            .unwrap(),
            R_INVALID_IDENTITY
        );
        assert_eq!(
            run(IdOptions {
                identity: Some("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".into()),
                validate: vec![file.display().to_string()],
                ..Default::default()
            })
            .unwrap(),
            R_INVALID_IDENTITY
        );

        assert_eq!(
            run(IdOptions {
                identity: Some(id_path.display().to_string()),
                sign_message: Some("hello".into()),
                write: Some(dir.join("msg").display().to_string()),
                ..Default::default()
            })
            .unwrap(),
            0
        );
        assert_eq!(
            run(IdOptions {
                identity: Some(hash),
                no_cache: true,
                validate: vec![dir.join("msg.rsm").display().to_string()],
                config: Some(dir.clone()),
                ..Default::default()
            })
            .unwrap(),
            0
        );
        assert_eq!(
            run(IdOptions {
                identity: Some("short".into()),
                validate: vec![dir.join("msg.rsm").display().to_string()],
                ..Default::default()
            })
            .unwrap(),
            R_INVALID_IDENTITY
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_recall_does_not_rewrite_known_destinations() {
        let dir = std::env::temp_dir().join(format!("rnid-known-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let hash = *identity.address_hash();
        let mut known = reticulum::storage::KnownDestinations::new();
        known.remember(
            [9u8; 32],
            hash,
            identity.as_identity().to_bytes(),
            Some(b"keep-me".to_vec()),
            12.0,
        );
        let storage_dir = dir.join("storage");
        std::fs::create_dir_all(&storage_dir).unwrap();
        let storage = reticulum::storage::FsStorage::new(storage_dir.display().to_string());
        known.save(&storage).unwrap();
        let path = storage_dir.join("known_destinations");
        let before = std::fs::read(&path).unwrap();
        assert!(!before.is_empty());
        let found = recall_from_disk(&dir, &hash).expect("disk recall");
        assert_eq!(found.address_hash, hash);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            run(IdOptions {
                config: Some(dir.clone()),
                identity: Some(hash.to_hex_string()),
                hash: Some("example.aspect".into()),
                ..Default::default()
            })
            .unwrap(),
            0
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_public_rejects_unparsable_verifying_key() {
        let dir = std::env::temp_dir().join(format!("rnid-pub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let good = dir.join("good.pub");
        std::fs::write(&good, identity.as_identity().to_bytes()).unwrap();
        assert_eq!(
            run(IdOptions {
                import_pub: Some(good.display().to_string()),
                print_identity: true,
                ..Default::default()
            })
            .unwrap(),
            0
        );
        let mut bad_bytes = identity.as_identity().to_bytes();
        let mut rejected = false;
        for tweak in 0u8..=255 {
            bad_bytes[32] = tweak;
            let parsed = Identity::new_from_slices(&bad_bytes[..32], &bad_bytes[32..]);
            if parsed.to_bytes().as_slice() != bad_bytes.as_slice() {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "expected an unparsable verifying key");
        let bad = dir.join("bad.pub");
        std::fs::write(&bad, bad_bytes).unwrap();
        assert_eq!(
            run(IdOptions {
                import_pub: Some(bad.display().to_string()),
                print_identity: true,
                ..Default::default()
            })
            .unwrap(),
            R_INVALID_IDENTITY
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timeout_rejects_non_finite_and_overflow() {
        assert_eq!(
            path_request_timeout(f64::INFINITY).unwrap_err(),
            R_INVALID_ARGS
        );
        assert_eq!(
            path_request_timeout(f64::NEG_INFINITY).unwrap_err(),
            R_INVALID_ARGS
        );
        assert_eq!(path_request_timeout(f64::NAN).unwrap_err(), R_INVALID_ARGS);
        assert_eq!(path_request_timeout(1e20).unwrap_err(), R_INVALID_ARGS);
        assert_eq!(path_request_timeout(0.0).unwrap(), Duration::ZERO);
        assert_eq!(path_request_timeout(-0.0).unwrap(), Duration::ZERO);
        assert_eq!(path_request_timeout(-1.0).unwrap(), Duration::ZERO);
        assert_eq!(
            path_request_timeout(1.5).unwrap(),
            Duration::from_secs_f64(1.5)
        );
    }

    struct StepReader<'a> {
        data: &'a [u8],
        pos: usize,
        step: usize,
    }

    impl Read for StepReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let count = self.step.min(buf.len()).min(self.data.len() - self.pos);
            buf[..count].copy_from_slice(&self.data[self.pos..self.pos + count]);
            self.pos += count;
            Ok(count)
        }
    }

    #[test]
    fn read_chunk_fills_across_short_reads() {
        let data = [1u8, 2, 3, 4, 5, 6, 7];
        let mut reader = StepReader {
            data: &data,
            pos: 0,
            step: 1,
        };
        let mut buf = [0u8; 5];
        assert_eq!(read_chunk(&mut reader, &mut buf).unwrap(), 5);
        assert_eq!(buf, [1, 2, 3, 4, 5]);
        let mut rest = [0u8; 5];
        assert_eq!(read_chunk(&mut reader, &mut rest).unwrap(), 2);
        assert_eq!(&rest[..2], &[6, 7]);
        assert_eq!(read_chunk(&mut reader, &mut rest).unwrap(), 0);
    }
}
