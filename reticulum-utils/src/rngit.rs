//! `rngit` — Reticulum git repositories.
//!
//! * The node announces a `git.repositories` SINGLE destination and serves
//!   the request paths `/git/{list,fetch,push,delete,create,fork,sync,mirror}`
//!   plus `/mgmt/{release,work,perms}` on top of a configured set of
//!   repository groups. Wire messages: request payloads are msgpack dicts
//!   keyed by the `IDX_*` integers and named fields, responses are a status
//!   byte (`RES_*`) plus an optional payload, and large payloads (git
//!   bundles, release artifacts) travel as resource responses carrying
//!   msgpack metadata.
//! * The client (`rngit create|release|perms|work|fork|sync|mirror`) and the
//!   `git-remote-rns` helper (git remote-helper protocol over stdin/stdout)
//!   use the same link + request machinery to talk to a node.
//!
//! A node or client attaches to a shared Reticulum instance when one is
//! reachable, like the other `rn*` tools.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reticulum::destination::link::{Link, LinkEvent, LinkEventData, LinkStatus};
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::{Identity, PrivateIdentity, Signature};
use reticulum::resource::manager::{RequestContext, RequestEvent};
use reticulum::resource::{msgpack_bin, ResourceOptions};
use reticulum::transport::Transport;
use tokio::sync::Mutex;

use crate::common::{
    build_tool_transport, load_or_create_private_identity, load_private_identity, prettyhexrep,
    resolve_config_dir, rmpv_to_bytes, ToolTransportOptions,
};
use crate::rnid::{decode_hex, expand_user, hex_encode, pack_rsg, sha256, unpack_rsg, verify_rsg};

pub const APP_NAME: &str = "git";
pub const DESTINATION_ASPECT: &str = "repositories";

const PATH_LIST: &str = "/git/list";
const PATH_FETCH: &str = "/git/fetch";
const PATH_PUSH: &str = "/git/push";
const PATH_DELETE: &str = "/git/delete";
const PATH_CREATE: &str = "/git/create";
const PATH_FORK: &str = "/git/fork";
const PATH_SYNC: &str = "/git/sync";
const PATH_MIRROR: &str = "/git/mirror";
const PATH_RELEASE: &str = "/mgmt/release";
const PATH_WORK: &str = "/mgmt/work";
const PATH_PERMS: &str = "/mgmt/perms";

const RES_OK: u8 = 0x00;
const RES_DISALLOWED: u8 = 0x01;
const RES_INVALID_REQ: u8 = 0x02;
const RES_NOT_FOUND: u8 = 0x03;
const RES_REMOTE_FAIL: u8 = 0xFF;

const IDX_REPOSITORY: u64 = 0x00;
const IDX_RESULT_CODE: u64 = 0x01;
const IDX_GROUP: u64 = 0x02;

const WORK_DOC_LIMIT: usize = 256 * 1024;
const CLONE_PROTOS: [&str; 4] = ["rns", "http", "https", "ssh"];
const REF_BATCH_SIZE: usize = 25;
const PATH_TIMEOUT: Duration = Duration::from_secs(15);
const LINK_TIMEOUT: Duration = Duration::from_secs(15);
const SIG_BYTES: usize = 64;
const KEY_BYTES: usize = 64;
const REPO_CREATE_PERMS_TEMPLATE: &str = "adm:{IDENTITY_HASH}";

const PROTO_SPEC: &str = "rns://";
const SIG_EXT: &str = "rsg";
const MSG_EXT: &str = "rsm";

const RELEASE_NOTES_TEMPLATE: &str = "# Enter release notes for {TAG}.\n\
     # Lines starting with '#' will be ignored.\n\
     # Save and exit the editor when done, or exit without saving to abort.\n";
const COMMENT_TEMPLATE: &str = "# Remove this line and enter your update. Save and exit when done, or save an empty document to abort abort.";
const CREATE_DOC_TEMPLATE: &str = "# Remove this line and enter your document content. Save and exit when done, or save an empty document to abort abort.";
const PERMISSIONS_TEMPLATE: &str = "# No permissions are currently defined for this entity. Add them below, and save and exit when you are done.";

// ---------------------------------------------------------------------------
// msgpack helpers
// ---------------------------------------------------------------------------

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// `rngit-{tag}-{pid}-{ms}-{n}{ext}` under the temp dir; `n` keeps
/// back-to-back paths inside one millisecond distinct.
fn temp_path(tag: &str, ext: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "rngit-{tag}-{}-{}-{unique}{ext}",
        std::process::id(),
        (now_f64() * 1000.0) as u64
    ))
}

fn unpack_value(data: &[u8]) -> Option<rmpv::Value> {
    rmpv::decode::read_value(&mut &data[..]).ok()
}

fn vstr(text: &str) -> rmpv::Value {
    rmpv::Value::String(text.into())
}

fn vbin(bytes: &[u8]) -> rmpv::Value {
    rmpv::Value::Binary(bytes.to_vec())
}

fn map_get<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn map_get_int(value: &rmpv::Value, key: u64) -> Option<&rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_u64() == Some(key))
        .map(|(_, item)| item)
}

fn value_str(value: &rmpv::Value) -> Option<String> {
    match value {
        rmpv::Value::String(s) => s.as_str().map(str::to_string),
        _ => None,
    }
}

fn value_bin(value: &rmpv::Value) -> Option<&[u8]> {
    match value {
        rmpv::Value::Binary(b) => Some(b.as_slice()),
        _ => None,
    }
}

fn value_bool(value: &rmpv::Value) -> bool {
    matches!(value, rmpv::Value::Boolean(true))
}

fn value_i64(value: &rmpv::Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_u64().map(|v| v as i64))
}

fn value_f64(value: &rmpv::Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|v| v as f64))
        .or_else(|| value.as_u64().map(|v| v as f64))
}

// ---------------------------------------------------------------------------
// Ref and SHA sanitizers (git-check-ref-format)
// ---------------------------------------------------------------------------

pub fn san_ref(reference: &str) -> Option<&str> {
    if reference.starts_with('-')
        || reference.starts_with('/')
        || reference.ends_with('/')
        || reference.ends_with('.')
    {
        return None;
    }
    if reference.contains(' ')
        || !reference.contains('/')
        || reference.contains("..")
        || reference.contains("/.")
        || reference.contains("//")
        || reference.contains('\\')
    {
        return None;
    }
    for component in reference.split('/') {
        if component.ends_with(".lock") {
            return None;
        }
    }
    if !reference.chars().all(|c| (c as u32) >= 40) {
        return None;
    }
    for bad in ['\x7f', '~', '^', ':', '?', '*', '['] {
        if reference.contains(bad) {
            return None;
        }
    }
    if reference.contains("@{") || reference == "@" {
        return None;
    }
    Some(reference)
}

fn san_sha(sha: &str) -> Option<&str> {
    if sha.len() < 40 {
        return None;
    }
    decode_hex(&sha[..sha.len() & !1])?;
    Some(sha)
}

// ---------------------------------------------------------------------------
// Config file handling (Python ConfigObj-style)
// ---------------------------------------------------------------------------

/// One section of a ConfigObj-style file.
#[derive(Debug, Default, Clone)]
struct IniSection {
    entries: Vec<(String, String)>,
}

impl IniSection {
    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    fn get_int(&self, key: &str) -> Option<i64> {
        self.get(key)?.trim().parse().ok()
    }

    /// `key = a, b, c` splits like ConfigObj `as_list`.
    fn get_list(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(value) => value
                .split(',')
                .map(|item| item.trim().trim_matches('"').trim_matches('\'').to_string())
                .filter(|item| !item.is_empty())
                .collect(),
            None => Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct IniFile {
    /// Entries before the first `[section]` header.
    root: IniSection,
    sections: Vec<(String, IniSection)>,
}

impl IniFile {
    fn section(&self, name: &str) -> Option<&IniSection> {
        self.sections
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, section)| section)
    }
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Parse a ConfigObj-style file: `[section]` headers, `key = value`,
/// `#` comments, deeper `[ [nested] ]` sections flattened away (kept as
/// dotted data the node never uses).
fn parse_ini(text: &str) -> IniFile {
    let mut file = IniFile::default();
    let mut current: Option<usize> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line.trim_matches(['[', ']']).trim().to_string();
            file.sections.push((name, IniSection::default()));
            current = Some(file.sections.len() - 1);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_string();
        let value = unquote(value);
        match current {
            Some(index) => file.sections[index].1.entries.push((key, value)),
            None => file.root.entries.push((key, value)),
        }
    }
    file
}

// ---------------------------------------------------------------------------
// Permissions (allowed files and [access] config section)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Perm {
    Read,
    Write,
    Create,
    Stats,
    Release,
    Interact,
    Propose,
    Admin,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Target {
    Nobody,
    All,
    Identity([u8; 16]),
}

#[derive(Clone, Default, Debug)]
struct PermSet {
    read: HashSet<Target>,
    write: HashSet<Target>,
    create: HashSet<Target>,
    stats: HashSet<Target>,
    release: HashSet<Target>,
    interact: HashSet<Target>,
    propose: HashSet<Target>,
    admin: HashSet<Target>,
}

impl PermSet {
    fn get(&self, perm: Perm) -> &HashSet<Target> {
        match perm {
            Perm::Read => &self.read,
            Perm::Write => &self.write,
            Perm::Create => &self.create,
            Perm::Stats => &self.stats,
            Perm::Release => &self.release,
            Perm::Interact => &self.interact,
            Perm::Propose => &self.propose,
            Perm::Admin => &self.admin,
        }
    }
}

type Aliases = HashMap<String, String>;

/// Alias lookup. `is_target` keeps the permission shorthands (`all`,
/// `none`, `everyone`, ...) unresolvable, as permission targets need them
/// verbatim; destination aliases do not.
fn resolve_alias<'a>(aliases: &'a Aliases, alias: &'a str, is_target: bool) -> &'a str {
    if is_target
        && matches!(
            alias.to_lowercase().as_str(),
            "n" | "none" | "nobody" | "a" | "all" | "everyone"
        )
    {
        return alias;
    }
    if alias.len() == 32 && decode_hex(alias).is_some() {
        return alias;
    }
    aliases.get(alias).map(String::as_str).unwrap_or(alias)
}

fn parse_target(target: &str, aliases: &Aliases) -> Option<Target> {
    let resolved = resolve_alias(aliases, target, true);
    match resolved.to_lowercase().as_str() {
        "n" | "none" | "nobody" => Some(Target::Nobody),
        "a" | "all" | "everyone" => Some(Target::All),
        _ => {
            if resolved.len() == 32 {
                let bytes = decode_hex(resolved)?;
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&bytes[..16]);
                Some(Target::Identity(hash))
            } else {
                None
            }
        }
    }
}

fn apply_permission_line(set: &mut PermSet, perm: Perm, target: Target, is_rw: bool) {
    let perms: &[Perm] = if is_rw {
        &[Perm::Read, Perm::Write]
    } else {
        std::slice::from_ref(&perm)
    };
    for &p in perms {
        match p {
            Perm::Read => {
                set.read.insert(target.clone());
            }
            Perm::Write => {
                set.write.insert(target.clone());
            }
            Perm::Create => {
                set.create.insert(target.clone());
            }
            Perm::Stats => {
                set.stats.insert(target.clone());
            }
            Perm::Release => {
                set.release.insert(target.clone());
            }
            Perm::Interact => {
                set.interact.insert(target.clone());
            }
            Perm::Propose => {
                set.propose.insert(target.clone());
            }
            Perm::Admin => {
                set.admin.insert(target.clone());
            }
        }
    }
}

fn apply_permission_text(set: &mut PermSet, input: &str, aliases: &Aliases) {
    for entry in input.lines() {
        let entry = entry.trim();
        if entry.starts_with('#') || entry.is_empty() {
            continue;
        }
        if let Some(((perm, is_rw), target)) = parse_permission_full(entry, aliases) {
            apply_permission_line(set, perm, target, is_rw);
        }
    }
}

/// Parse one `perm:target` line; `rw` expands to read+write at apply time.
/// Returns `((perm, is_readwrite), target)`.
fn parse_permission_full(entry: &str, aliases: &Aliases) -> Option<((Perm, bool), Target)> {
    let (perm, target) = entry.split_once(':')?;
    let (perm, is_rw) = match perm.to_lowercase().as_str() {
        "r" | "read" => (Perm::Read, false),
        "w" | "write" => (Perm::Write, false),
        "rw" | "readwrite" => (Perm::Read, true),
        "c" | "create" => (Perm::Create, false),
        "s" | "stats" => (Perm::Stats, false),
        "rel" | "release" => (Perm::Release, false),
        "i" | "interact" => (Perm::Interact, false),
        "p" | "propose" => (Perm::Propose, false),
        "adm" | "admin" => (Perm::Admin, false),
        _ => return None,
    };
    Some(((perm, is_rw), parse_target(target, aliases)?))
}

/// Parse an `.allowed` file's content into a permission set.
fn permissions_from_allowed_input(allowed_input: &str, aliases: &Aliases) -> PermSet {
    let mut set = PermSet::default();
    apply_permission_text(&mut set, allowed_input, aliases);
    set
}

/// Read an `.allowed` file; when it is executable, run it and use its
/// stdout. Returns (perms, dynamic).
fn load_allowed_permissions(allowed_path: &Path, aliases: &Aliases) -> (PermSet, bool) {
    if !allowed_path.is_file() {
        return (PermSet::default(), false);
    }
    if allowed_path_is_executable(allowed_path) {
        let output = std::process::Command::new(allowed_path)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        return (permissions_from_allowed_input(&output, aliases), true);
    }
    let input = std::fs::read_to_string(allowed_path).unwrap_or_default();
    (permissions_from_allowed_input(&input, aliases), false)
}

fn allowed_path_is_executable(allowed_path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        allowed_path
            .metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = allowed_path;
        false
    }
}

fn remote_hash(identity: &Identity) -> [u8; 16] {
    let mut hash = [0u8; 16];
    hash.copy_from_slice(identity.address_hash.as_slice());
    hash
}

// ---------------------------------------------------------------------------
// Repository group model
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Repository {
    path: PathBuf,
    /// `git config repository.rngit.upstream.source` when type == fork.
    fork: Option<String>,
    /// Same for mirrors.
    mirror: Option<String>,
    perms: PermSet,
}

#[derive(Debug)]
struct Group {
    path: PathBuf,
    dynamic_perms: bool,
    perms: PermSet,
    repositories: HashMap<String, Repository>,
}

// ---------------------------------------------------------------------------
// Node state
// ---------------------------------------------------------------------------

struct GitNode {
    identity: PrivateIdentity,
    node_name: String,
    announce_interval: u64,
    mirror_interval: u64,
    sync_check_interval: u64,
    blocked: HashSet<[u8; 16]>,
    aliases: Aliases,
    groups: HashMap<String, Group>,
    last_announce: f64,
    last_sync_check: f64,
}

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn git(repo: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    tokio::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .await
}

async fn git_text(repo: &Path, args: &[&str]) -> Option<String> {
    let output = git(repo, args).await.ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn is_git_repository(path: &Path) -> bool {
    matches!(
        git_text(path, &["rev-parse", "--git-dir"]).await.as_deref(),
        Some(".")
    )
}

async fn is_bare_repository(path: &Path) -> bool {
    matches!(
        git_text(path, &["config", "--bool", "core.bare"])
            .await
            .as_deref(),
        Some("true")
    )
}

async fn rngit_repo_type(path: &Path) -> Option<(String, String)> {
    let kind = git_text(path, &["config", "repository.rngit.type"]).await?;
    if kind != "fork" && kind != "mirror" {
        return None;
    }
    let source = git_text(path, &["config", "repository.rngit.upstream.source"]).await?;
    Some((kind, source))
}

async fn mirror_synced(path: &Path) -> i64 {
    git_text(path, &["config", "repository.rngit.upstream.sync"])
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

async fn set_mirror_synced(path: &Path) -> bool {
    git(
        path,
        &[
            "config",
            "repository.rngit.upstream.sync",
            &format!("{}", now_f64() as i64),
        ],
    )
    .await
    .map(|o| o.status.success())
    .unwrap_or(false)
}

async fn update_head_to_source_default(repo_path: &Path, source_url: &str) -> bool {
    let mut target_branch: Option<String> = None;
    if let Ok(output) = tokio::process::Command::new("git")
        .args(["ls-remote", "--symref", source_url, "HEAD"])
        .output()
        .await
    {
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some((reference, head)) = line.split_once('\t') {
                    if head == "HEAD" {
                        if let Some(branch) = reference.strip_prefix("ref: ") {
                            if branch.starts_with("refs/heads/") {
                                target_branch = Some(branch.trim().to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(branch) = &target_branch {
        let check = git(repo_path, &["show-ref", "--verify", "--quiet", branch])
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !check {
            target_branch = None;
        }
    }
    if target_branch.is_none() {
        match git_text(
            repo_path,
            &[
                "for-each-ref",
                "--format=%(refname:short)",
                "refs/heads",
                "--count=1",
            ],
        )
        .await
        {
            Some(first) if !first.is_empty() => {
                target_branch = Some(format!("refs/heads/{first}"));
            }
            _ => return false,
        }
    }
    let Some(branch) = target_branch else {
        return false;
    };
    git(repo_path, &["symbolic-ref", "HEAD", &branch])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

impl GitNode {
    fn resolve_permission(
        &self,
        remote_identity: &Identity,
        group_name: &str,
        repository_name: &str,
        permission: Perm,
    ) -> bool {
        let hash = remote_hash(remote_identity);
        if self.blocked.contains(&hash) {
            return false;
        }
        let Some(group) = self.groups.get(group_name) else {
            return false;
        };
        let Some(repo) = group.repositories.get(repository_name) else {
            return false;
        };
        let repository_permissions = repo.perms.get(permission);
        let group_permissions = group.perms.get(permission);
        let repository_admins = &repo.perms.admin;
        let group_admins = &group.perms.admin;
        let remote = Target::Identity(hash);

        if repository_permissions.contains(&Target::Nobody) {
            return false;
        }
        if repository_permissions.contains(&Target::All)
            || repository_permissions.contains(&remote)
            || repository_admins.contains(&remote)
        {
            return true;
        }
        if !repository_permissions.is_empty() {
            return false;
        }
        if group_permissions.contains(&Target::Nobody) {
            return false;
        }
        group_permissions.contains(&Target::All)
            || group_permissions.contains(&remote)
            || group_admins.contains(&remote)
    }

    fn resolve_group_permission(
        &self,
        remote_identity: &Identity,
        group_name: &str,
        permission: Perm,
    ) -> bool {
        let hash = remote_hash(remote_identity);
        let Some(group) = self.groups.get(group_name) else {
            return false;
        };
        let group_permissions = group.perms.get(permission);
        let group_admins = &group.perms.admin;
        let remote = Target::Identity(hash);
        if group_permissions.contains(&Target::Nobody) {
            return false;
        }
        group_permissions.contains(&Target::All)
            || group_permissions.contains(&remote)
            || group_admins.contains(&remote)
    }

    fn resolve_doc_permission(
        &self,
        remote_identity: &Identity,
        group_name: &str,
        repository_name: &str,
        doc_id: i64,
        permission: Perm,
    ) -> bool {
        let hash = remote_hash(remote_identity);
        let Some(group) = self.groups.get(group_name) else {
            return false;
        };
        let Some(repo) = group.repositories.get(repository_name) else {
            return false;
        };
        let work_path = format!("{}.work", repo.path.display());
        let doc_allowed_path = format!("{work_path}/{doc_id}.allowed");
        let mut doc_permissions = PermSet::default();
        if Path::new(&work_path).is_dir() && Path::new(&doc_allowed_path).is_file() {
            if let Ok(input) = std::fs::read_to_string(&doc_allowed_path) {
                doc_permissions = permissions_from_allowed_input(&input, &self.aliases);
            }
        }
        let repository_permissions = repo.perms.get(permission);
        let group_permissions = group.perms.get(permission);
        let doc_permissions_ref = doc_permissions.get(permission);
        let repository_admins = &repo.perms.admin;
        let group_admins = &group.perms.admin;
        let doc_admins = &doc_permissions.admin;
        let remote = Target::Identity(hash);

        if doc_permissions_ref.contains(&Target::Nobody) {
            return false;
        }
        if doc_permissions_ref.contains(&Target::All)
            || doc_permissions_ref.contains(&remote)
            || doc_admins.contains(&remote)
        {
            return true;
        }
        if repository_permissions.contains(&Target::Nobody) {
            return false;
        }
        if repository_permissions.contains(&Target::All)
            || repository_permissions.contains(&remote)
            || repository_admins.contains(&remote)
        {
            return true;
        }
        if !repository_permissions.is_empty() {
            return false;
        }
        if group_permissions.contains(&Target::Nobody) {
            return false;
        }
        group_permissions.contains(&Target::All)
            || group_permissions.contains(&remote)
            || group_admins.contains(&remote)
    }

    async fn load_repository_group(&mut self, group_name: &str, group_path: PathBuf) {
        let group = self
            .groups
            .entry(group_name.to_string())
            .or_insert_with(|| Group {
                path: group_path.clone(),
                dynamic_perms: false,
                perms: PermSet::default(),
                repositories: HashMap::new(),
            });
        if group.path != group_path {
            log::error!("Repository group path did not match existing entry while loading {group_name}, aborting load");
            return;
        }
        self.update_group_permissions(group_name);
        let mut loaded = 0;
        if let Some(group) = self.groups.get_mut(group_name) {
            if let Ok(entries) = std::fs::read_dir(&group_path) {
                let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
                paths.sort();
                for path in paths {
                    if load_repository(group, path, &self.aliases).await {
                        loaded += 1;
                    }
                }
            }
        }
        log::debug!("Loaded {loaded} repositories for group \"{group_name}\"");
    }

    fn update_group_permissions(&mut self, group_name: &str) {
        let Some(group) = self.groups.get(group_name) else {
            return;
        };
        let mut new_permissions = PermSet::default();
        let group_path = group.path.clone();
        let allowed_path = PathBuf::from(format!("{}.allowed", group_path.display()));
        if allowed_path.is_file() {
            let (group_permissions, dynamic_perms) =
                load_allowed_permissions(&allowed_path, &self.aliases);
            new_permissions = group_permissions;
            if let Some(group) = self.groups.get_mut(group_name) {
                group.dynamic_perms = dynamic_perms;
            }
        } else if let Some(group) = self.groups.get_mut(group_name) {
            group.dynamic_perms = false;
        }
        if let Some(group) = self.groups.get_mut(group_name) {
            group.perms = new_permissions;
        }
    }

    /// Apply `[access]` config-section permissions for a group after the
    /// `.allowed` file pass.
    fn apply_config_access(&mut self, group_name: &str, config_access: &IniSection) {
        for entry in config_access.entries_for(group_name) {
            if let Some(((perm, is_rw), target)) = parse_permission_full(&entry, &self.aliases) {
                if let Some(group) = self.groups.get_mut(group_name) {
                    apply_permission_line(&mut group.perms, perm, target, is_rw);
                }
            }
        }
    }

    async fn load_repository(&mut self, group_name: &str, path: PathBuf) -> bool {
        let Some(group) = self.groups.get_mut(group_name) else {
            return false;
        };
        load_repository(group, path, &self.aliases).await
    }
}

impl IniSection {
    /// ConfigObj `section[group]` values as a list of permission lines.
    fn entries_for(&self, group_name: &str) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(name, _)| name == group_name)
            .flat_map(|(_, value)| {
                value
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<String>>()
            })
            .collect()
    }
}

fn finish_repository_load(
    group: &mut Group,
    path: &Path,
    aliases: &Aliases,
    fork: Option<String>,
    mirror: Option<String>,
) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
        return false;
    };
    let allowed_path = PathBuf::from(format!("{}.allowed", path.display()));
    let (perms, _dynamic) = load_allowed_permissions(&allowed_path, aliases);
    group.repositories.insert(
        name.clone(),
        Repository {
            path: path.to_path_buf(),
            fork,
            mirror,
            perms,
        },
    );
    true
}

async fn load_repository(group: &mut Group, path: PathBuf, aliases: &Aliases) -> bool {
    if !(path.is_dir() && !path.ends_with(".work") && !path.ends_with(".releases")) {
        return false;
    }
    if !is_git_repository(&path).await {
        log::warn!(
            "The directory \"{}\" is not a git repository, skipping",
            path.display()
        );
        return false;
    }
    if !is_bare_repository(&path).await {
        log::warn!(
            "The directory \"{}\" is not a bare git repository, skipping",
            path.display()
        );
        return false;
    }
    let (fork, mirror) = match rngit_repo_type(&path).await {
        Some((kind, source)) if kind == "fork" => (Some(source), None),
        Some((kind, source)) if kind == "mirror" => (None, Some(source)),
        _ => (None, None),
    };
    finish_repository_load(group, &path, aliases, fork, mirror)
}

// ---------------------------------------------------------------------------
// Request outcomes
// ---------------------------------------------------------------------------

enum Outcome {
    /// `[request_id, bin(payload)]` packet or plain-resource response.
    Bytes(Vec<u8>),
    /// Resource response carrying msgpack metadata.
    File {
        data: Vec<u8>,
        metadata: rmpv::Value,
    },
}

fn res_bytes(code: u8, message: &str) -> Outcome {
    let mut payload = Vec::with_capacity(1 + message.len());
    payload.push(code);
    payload.extend_from_slice(message.as_bytes());
    Outcome::Bytes(payload)
}

fn res_ok() -> Outcome {
    Outcome::Bytes(vec![RES_OK])
}

fn res_ok_data(payload: &[u8]) -> Outcome {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(RES_OK);
    out.extend_from_slice(payload);
    Outcome::Bytes(out)
}

/// `group/repository` request path: exactly two components, each at most
/// 256 bytes.
fn parse_request_repository_path(path: &str) -> Option<(&str, &str)> {
    let mut parts = path.split('/');
    let group = parts.next()?;
    let repository = parts.next()?;
    if parts.next().is_some() || group.len() > 256 || repository.len() > 256 {
        return None;
    }
    Some((group, repository))
}

/// Handler precondition: link identified + request data is a dict.
/// `ctx.data` carries the request payload's msgpack encoding.
fn identified_map(ctx: &RequestContext) -> Option<(Identity, rmpv::Value)> {
    let remote = ctx.remote_identity?;
    let data = unpack_value(&ctx.data)?;
    if !data.is_map() {
        return None;
    }
    Some((remote, data))
}

// ---------------------------------------------------------------------------
// Node request handlers
// ---------------------------------------------------------------------------

async fn handle_list(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let for_push = map_get(data, "for_push").map(value_bool).unwrap_or(false);
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let access = if for_push {
        node.resolve_permission(remote, group_name, repo_name, Perm::Write)
    } else {
        node.resolve_permission(remote, group_name, repo_name, Perm::Read)
    };
    let read_access = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
    if !access {
        return if read_access {
            res_bytes(RES_NOT_FOUND, "Not allowed")
        } else {
            res_bytes(RES_NOT_FOUND, "Not found")
        };
    }
    let Some(repository) = node
        .groups
        .get(group_name)
        .and_then(|g| g.repositories.get(repo_name))
    else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let repo_path = repository.path.clone();
    let head_ref = std::fs::read(repo_path.join("HEAD"))
        .ok()
        .filter(|c| c.starts_with(b"ref: "))
        .map(|c| String::from_utf8_lossy(&c[5..]).trim().to_string())
        .unwrap_or_else(|| "master".to_string());
    let output = match git(
        &repo_path,
        &["for-each-ref", "--format", "%(objectname) %(refname)"],
    )
    .await
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        _ => return res_bytes(RES_REMOTE_FAIL, "Could not list refs"),
    };
    let mut seen = Vec::<String>::new();
    let mut out = String::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((_sha, name)) = line.split_once(' ') else {
            continue;
        };
        if !seen.iter().any(|s| s == name) {
            seen.push(name.to_string());
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(&format!("@{head_ref} HEAD\n"));
    res_ok_data(out.as_bytes())
}

async fn handle_fetch(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some(refs) = map_get(data, "refs").and_then(|v| v.as_array()) else {
        return res_bytes(RES_INVALID_REQ, "No refs specified");
    };
    if refs.is_empty() {
        return res_bytes(RES_INVALID_REQ, "No refs specified");
    }
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    if !node.resolve_permission(remote, group_name, repo_name, Perm::Read) {
        return res_bytes(RES_NOT_FOUND, "Not found");
    }
    let Some(repository) = node
        .groups
        .get(group_name)
        .and_then(|g| g.repositories.get(repo_name))
    else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let repo_dir = repository.path.clone();

    let mut refs_arg: Vec<String> = Vec::new();
    for entry in refs {
        let Some(reference) = map_get(entry, "ref").and_then(value_str) else {
            return res_bytes(RES_INVALID_REQ, "Invalid request");
        };
        if san_ref(&reference).is_none() {
            return res_bytes(RES_INVALID_REQ, "Invalid request");
        }
        refs_arg.push(reference);
        if let Some(have) = map_get(entry, "have").and_then(value_str) {
            if san_sha(&have).is_none() {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            }
            let exists = git(&repo_dir, &["cat-file", "-t", &have])
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if exists {
                refs_arg.push(format!("^{have}"));
            }
        }
    }
    if let Some(haves) = map_get(data, "have").and_then(|v| v.as_array()) {
        for have in haves {
            let Some(have) = value_str(have) else {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            };
            if san_sha(&have).is_none() {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            }
            let exists = git(&repo_dir, &["cat-file", "-t", &have])
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if exists {
                refs_arg.push(format!("^{have}"));
            }
        }
    }

    let temp_dir = temp_path("fetch", "");
    if std::fs::create_dir_all(&temp_dir).is_err() {
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    let bundle_path = temp_dir.join("fetch.bundle");
    let mut args = vec!["bundle", "create", "--no-progress"];
    args.push(bundle_path.to_str().unwrap_or("bundle"));
    for arg in &refs_arg {
        args.push(arg.as_str());
    }
    let created = git(&repo_dir, &args).await;
    let ok = matches!(&created, Ok(o) if o.status.success());
    if !ok || !bundle_path.is_file() {
        let stderr = created
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stderr).to_lowercase())
            .unwrap_or_default();
        let _ = std::fs::remove_dir_all(&temp_dir);
        if stderr.contains("empty bundle") {
            // All objects reachable from the requested refs are already
            // available to the client; success with no bundle data.
            return res_ok();
        }
        return res_bytes(RES_REMOTE_FAIL, "Could not fetch refs");
    }
    let bundle = match std::fs::read(&bundle_path) {
        Ok(data) => data,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&temp_dir);
            return res_bytes(RES_REMOTE_FAIL, "Remote failure");
        }
    };
    let _ = std::fs::remove_dir_all(&temp_dir);
    Outcome::File {
        data: bundle,
        metadata: rmpv::Value::Map(vec![(
            rmpv::Value::from(IDX_RESULT_CODE),
            rmpv::Value::from(RES_OK as u64),
        )]),
    }
}

async fn handle_push(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "No repository specified");
    };
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let read_access = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
    let write_access = node.resolve_permission(remote, group_name, repo_name, Perm::Write);
    if !write_access {
        return if !read_access {
            res_bytes(RES_NOT_FOUND, "Not found")
        } else {
            res_bytes(RES_DISALLOWED, "Not allowed")
        };
    }
    let Some(repository) = node
        .groups
        .get(group_name)
        .and_then(|g| g.repositories.get(repo_name))
    else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let repo_dir = repository.path.clone();
    let local_ref = map_get(data, "local_ref")
        .and_then(value_str)
        .and_then(|r| san_ref(&r).map(str::to_string));
    let remote_ref = map_get(data, "remote_ref")
        .and_then(value_str)
        .and_then(|r| san_ref(&r).map(str::to_string));
    let force = map_get(data, "force").map(value_bool).unwrap_or(false);
    let bundle_data = map_get(data, "bundle")
        .and_then(value_bin)
        .map(|b| b.to_vec());
    let operations = map_get(data, "operations")
        .and_then(|v| v.as_array())
        .cloned();

    if let Some(bundle_data) = bundle_data {
        let (Some(local_ref), Some(remote_ref)) = (local_ref, remote_ref) else {
            return res_bytes(RES_INVALID_REQ, "Missing ref specification");
        };
        let bundle_path = temp_path("push", ".bundle");
        if std::fs::write(&bundle_path, &bundle_data).is_err() {
            return res_bytes(RES_REMOTE_FAIL, "Remote error");
        }
        let verified = git(
            &repo_dir,
            &["bundle", "verify", &bundle_path.to_string_lossy()],
        )
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
        if !verified {
            let _ = std::fs::remove_file(&bundle_path);
            return res_bytes(RES_REMOTE_FAIL, "Could not verify bundle");
        }
        let mut args = vec![
            "fetch".to_string(),
            bundle_path.to_string_lossy().to_string(),
            format!("{local_ref}:{remote_ref}"),
        ];
        if force {
            args.push("--force".to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let fetched = git(&repo_dir, &arg_refs)
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        let _ = std::fs::remove_file(&bundle_path);
        if !fetched {
            return res_bytes(RES_REMOTE_FAIL, "Could not verify bundle");
        }
        res_ok()
    } else if let Some(operations) = operations {
        for op in &operations {
            let action = map_get(op, "action")
                .and_then(value_str)
                .unwrap_or_default();
            if action != "update_ref" {
                return res_bytes(RES_INVALID_REQ, &format!("Unknown operation: {action}"));
            }
            let Some(reference) = map_get(op, "ref")
                .and_then(value_str)
                .and_then(|r| san_ref(&r).map(str::to_string))
            else {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            };
            if !reference.starts_with("refs/") {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            }
            let Some(sha) = map_get(op, "sha")
                .and_then(value_str)
                .and_then(|s| san_sha(&s).map(str::to_string))
            else {
                return res_bytes(RES_INVALID_REQ, "Invalid SHA");
            };
            let op_force = map_get(op, "force").map(value_bool).unwrap_or(false);
            let exists = git(&repo_dir, &["cat-file", "-t", &sha])
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !exists {
                return res_bytes(
                    RES_REMOTE_FAIL,
                    &format!("Object {sha} does not exist in repository"),
                );
            }
            let existing = git(&repo_dir, &["rev-parse", &reference])
                .await
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
            if let Some(existing_sha) = existing {
                if existing_sha != sha && !op_force {
                    return res_bytes(
                        RES_DISALLOWED,
                        &format!(
                            "Ref {reference} already exists at different SHA (force required)"
                        ),
                    );
                }
            }
            let updated = git(&repo_dir, &["update-ref", &reference, &sha])
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !updated {
                return res_bytes(RES_REMOTE_FAIL, "Could not update refs");
            }
        }
        res_ok()
    } else {
        res_bytes(RES_INVALID_REQ, "Invalid request data")
    }
}

async fn handle_delete(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let write_access = node.resolve_permission(remote, group_name, repo_name, Perm::Write);
    let read_access = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
    if !write_access {
        return if !read_access {
            res_bytes(RES_NOT_FOUND, "Not found")
        } else {
            res_bytes(RES_DISALLOWED, "Not allowed")
        };
    }
    let Some(repository) = node
        .groups
        .get(group_name)
        .and_then(|g| g.repositories.get(repo_name))
    else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let Some(reference) = map_get(data, "ref").and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    if san_ref(&reference).is_none() || !reference.starts_with("refs/") {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    }
    let deleted = git(&repository.path, &["update-ref", "-d", &reference])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if deleted {
        res_ok()
    } else {
        res_bytes(RES_REMOTE_FAIL, "Remote failure")
    }
}

async fn handle_create(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some(group) = node.groups.get(group_name) else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let read_access = node.resolve_group_permission(remote, group_name, Perm::Read);
    let create_access = node.resolve_group_permission(remote, group_name, Perm::Create);
    if !group.path.exists() {
        return res_bytes(RES_NOT_FOUND, "Not found");
    }
    if !create_access {
        return if !read_access {
            res_bytes(RES_NOT_FOUND, "Not found")
        } else {
            res_bytes(RES_DISALLOWED, "Not allowed")
        };
    }
    let repo_dir = group.path.join(repo_name);
    let repository_exists = group.repositories.contains_key(repo_name) || repo_dir.exists();
    if repository_exists {
        let existing_read = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
        return if existing_read {
            res_bytes(RES_DISALLOWED, "Repository already exists")
        } else {
            res_bytes(RES_NOT_FOUND, "Not found")
        };
    }
    if std::fs::create_dir_all(&repo_dir).is_err() {
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    let initialized = git(&repo_dir, &["init", "--bare"])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !initialized {
        let _ = std::fs::remove_dir_all(&repo_dir);
        return res_bytes(RES_REMOTE_FAIL, "Could not initialize repository");
    }
    let allowed_path = PathBuf::from(format!("{}.allowed", repo_dir.display()));
    let identity_hash = hex_encode(remote.address_hash.as_slice());
    let allowed = REPO_CREATE_PERMS_TEMPLATE.replace("{IDENTITY_HASH}", &identity_hash);
    if std::fs::write(&allowed_path, format!("{allowed}\n")).is_err() {
        let _ = std::fs::remove_dir_all(&repo_dir);
        return res_bytes(RES_REMOTE_FAIL, "Could not initialize repository");
    }
    if !node.load_repository(group_name, repo_dir.clone()).await {
        let _ = std::fs::remove_dir_all(&repo_dir);
        return res_bytes(RES_REMOTE_FAIL, "Failed to register repository");
    }
    res_ok()
}

async fn clone_repository(
    node: &mut GitNode,
    remote: &Identity,
    data: &rmpv::Value,
    repo_type: &str,
) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some(source_url) = map_get(data, "source").and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "No source specified");
    };
    if source_url.is_empty() {
        return res_bytes(RES_INVALID_REQ, "No source specified");
    }
    let proto = source_url
        .to_lowercase()
        .split("://")
        .next()
        .unwrap_or("")
        .to_string();
    if !CLONE_PROTOS.contains(&proto.as_str()) {
        return res_bytes(RES_DISALLOWED, "Prohibited source URL");
    }
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some(group) = node.groups.get(group_name) else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let read_access = node.resolve_group_permission(remote, group_name, Perm::Read);
    let create_access = node.resolve_group_permission(remote, group_name, Perm::Create);
    if !group.path.exists() {
        return res_bytes(RES_NOT_FOUND, "Not found");
    }
    if !create_access {
        return if !read_access {
            res_bytes(RES_NOT_FOUND, "Not found")
        } else {
            res_bytes(RES_DISALLOWED, "Not allowed")
        };
    }
    let repo_dir = group.path.join(repo_name);
    let repository_exists = group.repositories.contains_key(repo_name) || repo_dir.exists();
    if repository_exists {
        let existing_read = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
        return if existing_read {
            res_bytes(RES_DISALLOWED, "Repository already exists")
        } else {
            res_bytes(RES_NOT_FOUND, "Not found")
        };
    }

    let temp_dir = temp_path(repo_type, "");
    let cleanup = |dir: &Path| {
        let _ = std::fs::remove_dir_all(dir);
    };
    if std::fs::create_dir_all(&temp_dir).is_err() {
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    let initialized = git(&temp_dir, &["init", "--bare"])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !initialized {
        cleanup(&temp_dir);
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    let fetched = git(&temp_dir, &["fetch", &source_url, "+refs/*:refs/*"])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !fetched {
        cleanup(&temp_dir);
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    if !update_head_to_source_default(&temp_dir, &source_url).await {
        log::warn!("Failed to update HEAD for repository cloned from {source_url}");
    }
    if !git(&temp_dir, &["config", "repository.rngit.type", repo_type])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        cleanup(&temp_dir);
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    if !git(
        &temp_dir,
        &["config", "repository.rngit.upstream.source", &source_url],
    )
    .await
    .map(|o| o.status.success())
    .unwrap_or(false)
    {
        cleanup(&temp_dir);
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    if !set_mirror_synced(&temp_dir).await {
        cleanup(&temp_dir);
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    let allowed_path = PathBuf::from(format!("{}.allowed", repo_dir.display()));
    let identity_hash = hex_encode(remote.address_hash.as_slice());
    let allowed = REPO_CREATE_PERMS_TEMPLATE.replace("{IDENTITY_HASH}", &identity_hash);
    if std::fs::write(&allowed_path, format!("{allowed}\n")).is_err() {
        cleanup(&temp_dir);
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    if std::fs::rename(&temp_dir, &repo_dir).is_err() {
        cleanup(&temp_dir);
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    if !node.load_repository(group_name, repo_dir).await {
        return res_bytes(RES_REMOTE_FAIL, "Remote failure");
    }
    res_ok()
}

async fn handle_sync(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let read = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
    let write = node.resolve_permission(remote, group_name, repo_name, Perm::Write);
    if !read {
        return res_bytes(RES_NOT_FOUND, "Not found");
    }
    if !write {
        return res_bytes(RES_DISALLOWED, "Not allowed");
    }
    let Some(repository) = node
        .groups
        .get(group_name)
        .and_then(|g| g.repositories.get(repo_name))
    else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let (source_url, is_mirror) = if let Some(source) = repository.mirror.clone() {
        (source, true)
    } else if let Some(source) = repository.fork.clone() {
        (source, false)
    } else {
        return res_bytes(RES_INVALID_REQ, "Repository is neither fork nor mirror");
    };
    let fetched = git(&repository.path, &["fetch", &source_url, "+refs/*:refs/*"])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !fetched {
        return res_bytes(
            RES_REMOTE_FAIL,
            if is_mirror {
                "Mirror sync failed"
            } else {
                "Fork sync failed"
            },
        );
    }
    if is_mirror {
        update_head_to_source_default(&repository.path, &source_url).await;
    }
    set_mirror_synced(&repository.path).await;
    res_ok()
}

/// Fork/mirror bookkeeping used by the node jobs loop.
async fn sync_repository(repo_dir: &Path, source_url: &str) -> bool {
    let fetched = git(repo_dir, &["fetch", source_url, "+refs/*:refs/*"])
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !fetched {
        return false;
    }
    update_head_to_source_default(repo_dir, source_url).await
}

// ---------------------------------------------------------------------------
// Releases (on-disk layout <repo>.releases/)
// ---------------------------------------------------------------------------

fn releases_path(repository: &Repository) -> PathBuf {
    PathBuf::from(format!("{}.releases", repository.path.display()))
}

fn release_meta_path(releases_dir: &Path, tag: &str) -> PathBuf {
    releases_dir.join(tag).join("META")
}

fn read_release_meta(releases_dir: &Path, tag: &str) -> Option<IniSection> {
    let text = std::fs::read_to_string(release_meta_path(releases_dir, tag)).ok()?;
    Some(parse_ini(&text).root)
}

fn write_release_meta(releases_dir: &Path, tag: &str, updates: &[(String, String)]) {
    let mut meta = read_release_meta(releases_dir, tag).unwrap_or_default();
    for (key, value) in updates {
        if let Some(entry) = meta.entries.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.clone();
        } else {
            meta.entries.push((key.clone(), value.clone()));
        }
    }
    let mut text = String::new();
    for (key, value) in &meta.entries {
        text.push_str(&format!("{key} = {value}\n"));
    }
    let _ = std::fs::write(release_meta_path(releases_dir, tag), text);
}

/// Release info dicts for the wire response.
fn releases_list_data(releases_dir: &Path) -> (Vec<rmpv::Value>, Option<String>) {
    let mut releases: Vec<(i64, rmpv::Value)> = Vec::new();
    let mut tags: HashMap<String, bool> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(releases_dir) {
        for entry in entries.flatten() {
            let release_dir = entry.path();
            if !release_dir.is_dir() {
                continue;
            }
            let Some(meta) = std::fs::read_to_string(release_dir.join("META"))
                .ok()
                .map(|text| parse_ini(&text).root)
            else {
                continue;
            };
            let tag = meta
                .get("tag")
                .map(str::to_string)
                .or_else(|| entry.file_name().to_str().map(str::to_string))
                .unwrap_or_default();
            let status = meta.get("status").unwrap_or("unknown").to_string();
            let created = meta
                .get("created")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);

            let mut preview = String::new();
            let mut notes_format = "markdown";
            for notes_file in ["RELEASE.md", "RELEASE.mu", "RELEASE.txt"] {
                let notes_path = release_dir.join(notes_file);
                if !notes_path.is_file() {
                    continue;
                }
                if let Ok(notes) = std::fs::read_to_string(&notes_path) {
                    preview = notes
                        .lines()
                        .filter(|l| !l.starts_with('#') && !l.starts_with('>'))
                        .collect::<Vec<_>>()
                        .join("\n")
                        .trim()
                        .to_string();
                    if notes_file.ends_with(".mu") {
                        notes_format = "micron";
                    } else if notes_file.ends_with(".txt") {
                        notes_format = "text";
                    }
                }
                break;
            }
            let artifacts = std::fs::read_dir(release_dir.join("artifacts"))
                .map(|entries| entries.flatten().filter(|e| e.path().is_file()).count())
                .unwrap_or(0);
            let info = rmpv::Value::Map(vec![
                (vstr("tag"), vstr(&tag)),
                (vstr("hash"), vstr(meta.get("hash").unwrap_or(""))),
                (vstr("created"), rmpv::Value::from(created as u64)),
                (vstr("status"), vstr(&status)),
                (
                    vstr("created_by"),
                    vstr(meta.get("created_by").unwrap_or("")),
                ),
                (vstr("preview"), vstr(&preview)),
                (vstr("format"), vstr(notes_format)),
                (vstr("artifacts"), rmpv::Value::from(artifacts as u64)),
            ]);
            tags.insert(tag, status == "published");
            releases.push((created, info));
        }
    }
    let latest = std::fs::read_to_string(releases_dir.join("latest"))
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| tags.get(t).copied().unwrap_or(false));
    releases.sort_by_key(|r| std::cmp::Reverse(r.0));
    (releases.into_iter().map(|(_, v)| v).collect(), latest)
}

/// `\x00 + packb({"releases": [...], "latest": tag|None})`.
fn list_releases_payload(releases_dir: &Path) -> Vec<u8> {
    let (releases, latest) = releases_list_data(releases_dir);
    let latest_value = latest.map(|t| vstr(&t)).unwrap_or(rmpv::Value::Nil);
    let mut payload = vec![RES_OK];
    payload.extend_from_slice(&rmpv_to_bytes(&rmpv::Value::Map(vec![
        (vstr("releases"), rmpv::Value::Array(releases)),
        (vstr("latest"), latest_value),
    ])));
    payload
}

/// Full info for one release dir.
fn release_data(release_dir: &Path, tag: &str) -> Option<rmpv::Value> {
    let meta = std::fs::read_to_string(release_dir.join("META"))
        .ok()
        .map(|text| parse_ini(&text).root)?;
    let mut notes = String::new();
    let mut notes_format = "text";
    for (notes_file, fmt) in [("RELEASE.md", "markdown"), ("RELEASE.mu", "micron")] {
        let notes_path = release_dir.join(notes_file);
        if notes_path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&notes_path) {
                notes = text;
                notes_format = fmt;
            }
            break;
        }
    }
    let artifacts: Vec<rmpv::Value> = std::fs::read_dir(release_dir.join("artifacts"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().is_file())
                .map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    rmpv::Value::Map(vec![
                        (vstr("name"), vstr(&name)),
                        (vstr("size"), rmpv::Value::from(size)),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    let thanks = std::fs::read(release_dir.join("THANKS"))
        .ok()
        .and_then(|data| unpack_value(&data))
        .and_then(|v| map_get(&v, "count").and_then(value_i64))
        .unwrap_or(0);
    Some(rmpv::Value::Map(vec![
        (vstr("tag"), vstr(meta.get("tag").unwrap_or(tag))),
        (vstr("hash"), vstr(meta.get("hash").unwrap_or(""))),
        (
            vstr("created"),
            rmpv::Value::from(
                meta.get("created")
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(0) as u64,
            ),
        ),
        (
            vstr("status"),
            vstr(meta.get("status").unwrap_or("unknown")),
        ),
        (
            vstr("created_by"),
            vstr(meta.get("created_by").unwrap_or("")),
        ),
        (vstr("notes"), vstr(&notes)),
        (vstr("notes_format"), vstr(notes_format)),
        (vstr("artifacts"), rmpv::Value::Array(artifacts)),
        (vstr("thanks"), rmpv::Value::from(thanks as u64)),
    ]))
}

fn resolve_release_tag(releases_dir: &Path, tag: &str) -> Option<String> {
    if tag != "latest" {
        return Some(tag.to_string());
    }
    let latest = std::fs::read_to_string(releases_dir.join("latest"))
        .ok()
        .map(|t| t.trim().to_string())?;
    if latest.is_empty() {
        None
    } else {
        Some(latest)
    }
}

async fn handle_release(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some(operation) = map_get(data, "operation").and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let read_access = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
    let release_access = node.resolve_permission(remote, group_name, repo_name, Perm::Release);
    if !read_access {
        return res_bytes(RES_NOT_FOUND, "Not found");
    }
    let access = match operation.as_str() {
        "create" | "delete" | "latest" => release_access && read_access,
        "list" | "view" | "fetch" => read_access,
        _ => false,
    };
    if !access {
        return res_bytes(RES_DISALLOWED, "Not allowed");
    }
    let Some(repository) = node
        .groups
        .get(group_name)
        .and_then(|g| g.repositories.get(repo_name))
    else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let repo_dir = repository.path.clone();
    let releases_dir = releases_path(repository);

    match operation.as_str() {
        "list" => Outcome::Bytes(list_releases_payload(&releases_dir)),
        "view" => {
            let tag = map_get(data, "tag").and_then(value_str).unwrap_or_default();
            if tag.is_empty() || tag.contains('/') {
                return res_bytes(RES_INVALID_REQ, "Invalid tag specified");
            }
            let Some(tag) = resolve_release_tag(&releases_dir, tag.trim()) else {
                return res_bytes(RES_NOT_FOUND, "No latest release found");
            };
            let release_dir = releases_dir.join(&tag);
            if !release_dir.is_dir() {
                return res_bytes(RES_NOT_FOUND, "Release not found");
            }
            match release_data(&release_dir, &tag) {
                Some(info) => res_ok_data(&rmpv_to_bytes(&info)),
                None => res_bytes(RES_REMOTE_FAIL, "Error getting release data"),
            }
        }
        "fetch" => {
            let tag = map_get(data, "tag").and_then(value_str).unwrap_or_default();
            if tag.is_empty() || tag.contains('/') {
                return res_bytes(RES_INVALID_REQ, "Invalid tag specified");
            }
            let artifact = map_get(data, "artifact")
                .and_then(value_str)
                .unwrap_or_default();
            if artifact.is_empty() || artifact.contains('/') || artifact == ".." {
                return res_bytes(RES_INVALID_REQ, "Invalid artifact specified");
            }
            let Some(tag) = resolve_release_tag(&releases_dir, tag.trim()) else {
                return res_bytes(RES_NOT_FOUND, "No latest release found");
            };
            let release_dir = releases_dir.join(&tag);
            if !release_dir.is_dir() {
                return res_bytes(RES_NOT_FOUND, "Release not found");
            }
            let artifact_path = release_dir
                .join("artifacts")
                .join(Path::new(&artifact).file_name().unwrap_or_default());
            let Ok(artifact_data) = std::fs::read(&artifact_path) else {
                return res_bytes(RES_NOT_FOUND, "Artifact not found");
            };
            Outcome::File {
                data: artifact_data,
                metadata: rmpv::Value::Map(vec![(vstr("name"), vbin(artifact.as_bytes()))]),
            }
        }
        "create" => {
            let Some(step) = map_get(data, "step").and_then(value_str) else {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            };
            match step.as_str() {
                "init" => {
                    let tag = map_get(data, "tag").and_then(value_str).unwrap_or_default();
                    if tag.is_empty() || tag.contains('/') {
                        return res_bytes(RES_INVALID_REQ, "Invalid tag specified");
                    }
                    let tag = match Path::new(&tag).file_name() {
                        Some(name) => name.to_string_lossy().to_string(),
                        None => tag,
                    };
                    if tag.is_empty() || tag == "." || tag == ".." {
                        return res_bytes(RES_INVALID_REQ, "Invalid tag name");
                    }
                    let tag_exists = git(
                        &repo_dir,
                        &["rev-parse", "--verify", &format!("refs/tags/{tag}")],
                    )
                    .await
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                    if !tag_exists {
                        return res_bytes(
                            RES_INVALID_REQ,
                            &format!("Tag '{tag}' does not exist in repository"),
                        );
                    }
                    if std::fs::create_dir_all(&releases_dir).is_err() {
                        return res_bytes(RES_REMOTE_FAIL, "Remote error");
                    }
                    let release_dir = releases_dir.join(&tag);
                    if release_dir.is_dir() {
                        return res_bytes(RES_DISALLOWED, "Release already exists");
                    }
                    if std::fs::create_dir_all(release_dir.join("artifacts")).is_err() {
                        return res_bytes(RES_REMOTE_FAIL, "Remote error");
                    }
                    let mut meta = vec![
                        ("tag".to_string(), tag.clone()),
                        ("created".to_string(), format!("{}", now_f64() as i64)),
                        ("status".to_string(), "draft".to_string()),
                        (
                            "created_by".to_string(),
                            hex_encode(remote.address_hash.as_slice()),
                        ),
                    ];
                    if let Some(hash) = map_get(data, "hash").and_then(value_str) {
                        meta.push(("hash".to_string(), hash));
                    }
                    write_release_meta(&releases_dir, &tag, &meta);
                    let notes = map_get(data, "notes")
                        .and_then(value_str)
                        .unwrap_or_default();
                    if !notes.is_empty() {
                        let format = map_get(data, "notes_format")
                            .and_then(value_str)
                            .unwrap_or_else(|| "markdown".to_string());
                        let notes_file = if format == "micron" {
                            "RELEASE.mu"
                        } else {
                            "RELEASE.md"
                        };
                        let _ = std::fs::write(release_dir.join(notes_file), &notes);
                    }
                    let _ = std::fs::write(
                        release_dir.join("THANKS"),
                        rmpv_to_bytes(&rmpv::Value::Map(vec![(
                            vstr("count"),
                            rmpv::Value::from(0u64),
                        )])),
                    );
                    res_ok()
                }
                "artifact" => {
                    let tag = map_get(data, "tag").and_then(value_str).unwrap_or_default();
                    let name = map_get(data, "artifact_name").and_then(value_str);
                    if tag.is_empty() || name.is_none() {
                        return res_bytes(RES_INVALID_REQ, "Missing tag or artifact name");
                    }
                    if tag.contains('/') {
                        return res_bytes(RES_INVALID_REQ, "Invalid tag specified");
                    }
                    let Some(artifact_data) = map_get(data, "artifact_data") else {
                        return res_bytes(RES_INVALID_REQ, "No artifact data");
                    };
                    let name = Path::new(&name.unwrap())
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let release_dir = releases_dir.join(&tag);
                    if !release_dir.is_dir() {
                        return res_bytes(RES_NOT_FOUND, "Release not found");
                    }
                    let meta = read_release_meta(&releases_dir, &tag).unwrap_or_default();
                    if meta.get("status") != Some("draft") {
                        return res_bytes(
                            RES_DISALLOWED,
                            "Release was finalized and is not writable",
                        );
                    }
                    let artifacts_dir = release_dir.join("artifacts");
                    if std::fs::create_dir_all(&artifacts_dir).is_err() {
                        return res_bytes(RES_REMOTE_FAIL, "Remote error");
                    }
                    let bytes = match artifact_data {
                        rmpv::Value::Binary(b) => b.to_vec(),
                        rmpv::Value::String(s) => {
                            s.as_str().unwrap_or_default().as_bytes().to_vec()
                        }
                        _ => return res_bytes(RES_INVALID_REQ, "No artifact data"),
                    };
                    if std::fs::write(artifacts_dir.join(&name), &bytes).is_err() {
                        return res_bytes(RES_REMOTE_FAIL, "Remote error");
                    }
                    res_ok()
                }
                "finalize" => {
                    let tag = map_get(data, "tag").and_then(value_str).unwrap_or_default();
                    if tag.is_empty() || tag.contains('/') {
                        return res_bytes(RES_INVALID_REQ, "Invalid tag specified");
                    }
                    let release_dir = releases_dir.join(&tag);
                    if !release_dir.is_dir() {
                        return res_bytes(RES_NOT_FOUND, "Release not found");
                    }
                    let meta = read_release_meta(&releases_dir, &tag).unwrap_or_default();
                    if meta.get("status") != Some("draft") {
                        return res_bytes(
                            RES_DISALLOWED,
                            "Release was finalized and is not writable",
                        );
                    }
                    write_release_meta(
                        &releases_dir,
                        &tag,
                        &[
                            ("status".to_string(), "published".to_string()),
                            ("published_at".to_string(), format!("{}", now_f64() as i64)),
                        ],
                    );
                    let latest_path = releases_dir.join("latest");
                    let tmp_path = releases_dir.join("latest.tmp");
                    if std::fs::write(&tmp_path, &tag).is_ok() {
                        let _ = std::fs::rename(&tmp_path, &latest_path);
                    }
                    res_ok()
                }
                _ => res_bytes(RES_INVALID_REQ, "Invalid request"),
            }
        }
        "delete" => {
            let tag = map_get(data, "tag").and_then(value_str).unwrap_or_default();
            if tag.is_empty() || tag.contains('/') {
                return res_bytes(RES_INVALID_REQ, "Invalid tag specified");
            }
            let release_dir = releases_dir.join(&tag);
            if !release_dir.is_dir() {
                return res_bytes(RES_NOT_FOUND, "Release not found");
            }
            if std::fs::remove_dir_all(&release_dir).is_err() {
                return res_bytes(RES_REMOTE_FAIL, "Remote error");
            }
            res_ok()
        }
        "latest" => {
            let tag = map_get(data, "tag").and_then(value_str).unwrap_or_default();
            if tag.is_empty() || tag.contains('/') {
                return res_bytes(RES_INVALID_REQ, "Invalid tag specified");
            }
            let release_dir = releases_dir.join(&tag);
            if !release_dir.is_dir() {
                return res_bytes(RES_NOT_FOUND, "Release not found");
            }
            let latest_path = releases_dir.join("latest");
            let tmp_path = releases_dir.join("latest.tmp");
            if std::fs::write(&tmp_path, &tag).is_err()
                || std::fs::rename(&tmp_path, &latest_path).is_err()
            {
                return res_bytes(RES_REMOTE_FAIL, "Remote error");
            }
            res_ok()
        }
        _ => res_bytes(RES_INVALID_REQ, "Invalid request"),
    }
}

// ---------------------------------------------------------------------------
// Work documents (on-disk layout <repo>.work/)
// ---------------------------------------------------------------------------

fn doc_id_value(data: &rmpv::Value) -> Option<i64> {
    match map_get(data, "doc_id") {
        Some(v) => value_i64(v).or_else(|| value_str(v).and_then(|s| s.parse().ok())),
        None => None,
    }
}

/// Response `b"\x00" + packb(map)` helper for the packed-dict replies.
fn res_ok_map(pairs: Vec<(rmpv::Value, rmpv::Value)>) -> Outcome {
    res_ok_data(&rmpv_to_bytes(&rmpv::Value::Map(pairs)))
}

fn work_path(repository: &Repository) -> PathBuf {
    PathBuf::from(format!("{}.work", repository.path.display()))
}

const WORK_SCOPES: [&str; 3] = ["active", "completed", "proposed"];

fn find_scope_path(work_dir: &Path, doc_id: &str, scope: &str) -> Option<PathBuf> {
    let mut candidates: Vec<String> = WORK_SCOPES.iter().map(|s| s.to_string()).collect();
    if WORK_SCOPES.contains(&scope) {
        candidates.retain(|s| s == scope);
    }
    for candidate in candidates {
        let dir = work_dir.join(candidate).join(doc_id);
        if dir.is_dir() {
            return Some(dir);
        }
    }
    None
}

fn read_doc(root_path: &Path) -> Option<rmpv::Value> {
    let data = std::fs::read(root_path).ok()?;
    unpack_value(&data)
}

fn write_doc(root_path: &Path, content: &str, meta: &rmpv::Value) -> bool {
    let doc = rmpv::Value::Map(vec![
        (vstr("content"), vstr(content)),
        (vstr("meta"), meta.clone()),
    ]);
    std::fs::write(root_path, rmpv_to_bytes(&doc)).is_ok()
}

fn list_doc_ids(work_dir: &Path, scope: &str) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(work_dir.join(scope))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().is_dir())
                .filter(|entry| entry.path().join("root").is_file())
                .filter_map(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<i64>().ok())
                        .map(|id| id.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    ids.sort_by_key(|id| id.parse::<i64>().unwrap_or(0));
    ids
}

fn comments_list(doc_dir: &Path) -> Vec<rmpv::Value> {
    let mut comments: Vec<(i64, rmpv::Value)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(doc_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "root" {
                continue;
            }
            let Ok(comment_id) = name.parse::<i64>() else {
                continue;
            };
            if !entry.path().is_file() {
                continue;
            }
            let Some(data) = std::fs::read(entry.path())
                .ok()
                .and_then(|d| unpack_value(&d))
            else {
                continue;
            };
            let Some(meta) = map_get(&data, "meta") else {
                continue;
            };
            let created = map_get(meta, "created").and_then(value_f64).unwrap_or(0.0);
            let edited = map_get(meta, "edited").and_then(value_f64).unwrap_or(0.0);
            let author = map_get(meta, "author")
                .and_then(value_bin)
                .map(hex_encode)
                .unwrap_or_default();
            let format = map_get(meta, "format")
                .and_then(value_str)
                .unwrap_or_else(|| "markdown".into());
            comments.push((
                comment_id,
                rmpv::Value::Map(vec![
                    (vstr("id"), rmpv::Value::from(comment_id as u64)),
                    (
                        vstr("content"),
                        map_get(&data, "content")
                            .cloned()
                            .unwrap_or(rmpv::Value::Nil),
                    ),
                    (vstr("created"), rmpv::Value::F64(created)),
                    (vstr("edited"), rmpv::Value::F64(edited)),
                    (vstr("author"), vstr(&author)),
                    (vstr("format"), vstr(&format)),
                ]),
            ));
        }
    }
    comments.sort_by_key(|(id, _)| *id);
    comments.into_iter().map(|(_, c)| c).collect()
}

fn doc_list_data(
    node: &GitNode,
    remote: &Identity,
    repository: &Repository,
    group_name: &str,
    repo_name: &str,
    scope: &str,
) -> rmpv::Value {
    let work_dir = work_path(repository);
    let mut result: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
    for scope_name in WORK_SCOPES {
        let mut docs: Vec<(f64, rmpv::Value)> = Vec::new();
        if scope == scope_name || scope == "all" {
            for doc_id in list_doc_ids(&work_dir, scope_name) {
                let Ok(id) = doc_id.parse::<i64>() else {
                    continue;
                };
                if !node.resolve_doc_permission(remote, group_name, repo_name, id, Perm::Read) {
                    continue;
                }
                let doc_dir = work_dir.join(scope_name).join(&doc_id);
                let root_path = doc_dir.join("root");
                if !root_path.is_file() {
                    continue;
                }
                let Some(doc) = read_doc(&root_path) else {
                    continue;
                };
                let Some(meta) = map_get(&doc, "meta") else {
                    continue;
                };
                let author = map_get(meta, "author")
                    .and_then(value_bin)
                    .map(hex_encode)
                    .unwrap_or_default();
                let created = map_get(meta, "created").and_then(value_f64).unwrap_or(0.0);
                let edited = map_get(meta, "edited").and_then(value_f64).unwrap_or(0.0);
                let title = map_get(meta, "title")
                    .and_then(value_str)
                    .unwrap_or_else(|| "Untitled".into());
                let format = map_get(meta, "format")
                    .and_then(value_str)
                    .unwrap_or_else(|| "markdown".into());
                let comment_count = std::fs::read_dir(&doc_dir)
                    .map(|entries| {
                        entries
                            .flatten()
                            .filter(|e| {
                                e.path().is_file()
                                    && e.file_name()
                                        .to_str()
                                        .map(|n| n.parse::<i64>().is_ok())
                                        .unwrap_or(false)
                            })
                            .count()
                    })
                    .unwrap_or(0);
                docs.push((
                    created,
                    rmpv::Value::Map(vec![
                        (vstr("id"), rmpv::Value::from(id as u64)),
                        (vstr("title"), vstr(&title)),
                        (vstr("created"), rmpv::Value::F64(created)),
                        (vstr("edited"), rmpv::Value::F64(edited)),
                        (vstr("author"), vstr(&author)),
                        (vstr("format"), vstr(&format)),
                        (vstr("comments"), rmpv::Value::from(comment_count as u64)),
                    ]),
                ));
            }
        }
        docs.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        result.push((
            vstr(scope_name),
            rmpv::Value::Array(docs.into_iter().map(|(_, d)| d).collect()),
        ));
    }
    rmpv::Value::Map(result)
}

/// Validate the request's `signature` over `content`.
fn validate_doc_signature(remote: &Identity, content: &str, signature: &[u8]) -> bool {
    if signature.len() != SIG_BYTES {
        return false;
    }
    let Ok(sig_bytes) = <[u8; SIG_BYTES]>::try_from(signature) else {
        return false;
    };
    remote
        .verify(content.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

async fn handle_work(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some(operation) = map_get(data, "operation").and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    let Some(repository) = node
        .groups
        .get(group_name)
        .and_then(|g| g.repositories.get(repo_name))
    else {
        return res_bytes(RES_NOT_FOUND, "Not found");
    };
    let work_dir = work_path(repository);

    let mut read_access = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
    let mut write_access = node.resolve_permission(remote, group_name, repo_name, Perm::Write);
    let mut interact_access =
        node.resolve_permission(remote, group_name, repo_name, Perm::Interact);
    let propose_access = node.resolve_permission(remote, group_name, repo_name, Perm::Propose);
    let admin_access = node.resolve_permission(remote, group_name, repo_name, Perm::Admin);

    if !read_access {
        return res_bytes(RES_NOT_FOUND, "Not found");
    }

    // Document-level permission files can widen access for doc ops.
    let doc_id = doc_id_value(data);
    if let Some(id) = doc_id {
        if ["read", "view", "comment", "edit", "delete", "perms"].contains(&operation.as_str()) {
            read_access =
                node.resolve_doc_permission(remote, group_name, repo_name, id, Perm::Read)
                    || admin_access;
            if !read_access {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            }
        }
        if operation == "comment" {
            interact_access = interact_access
                || node.resolve_doc_permission(remote, group_name, repo_name, id, Perm::Interact);
        }
        if operation == "edit" {
            interact_access = interact_access
                || node.resolve_doc_permission(remote, group_name, repo_name, id, Perm::Interact);
            write_access = write_access
                || node.resolve_doc_permission(remote, group_name, repo_name, id, Perm::Write);
        }
    }

    let comment_access = interact_access && (read_access || write_access);
    let manage_access = interact_access && write_access;

    let access = match operation.as_str() {
        "list" | "view" => read_access,
        "comment" => comment_access,
        "propose" => propose_access,
        "create" | "edit" | "delete" | "complete" | "activate" => manage_access,
        "perms" => admin_access,
        _ => false,
    };
    if !access {
        return res_bytes(RES_DISALLOWED, "Not allowed");
    }

    let scope = map_get(data, "scope")
        .and_then(value_str)
        .unwrap_or_else(|| "active".to_string());
    let valid_scopes = ["active", "completed", "proposed", "all"];

    match operation.as_str() {
        "list" => res_ok_data(&rmpv_to_bytes(&doc_list_data(
            node, remote, repository, group_name, repo_name, &scope,
        ))),
        "view" => {
            if !valid_scopes.contains(&scope.as_str()) {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            }
            let Some(doc_id) = doc_id else {
                return res_bytes(RES_INVALID_REQ, "No document ID specified");
            };
            let Some(doc_dir) = find_scope_path(&work_dir, &doc_id.to_string(), "all") else {
                return res_bytes(RES_NOT_FOUND, "Not found");
            };
            let doc_scope = doc_dir
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let root_path = doc_dir.join("root");
            if !root_path.is_file() {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            }
            let Some(doc) = read_doc(&root_path) else {
                return res_bytes(RES_REMOTE_FAIL, "Error loading document");
            };
            let meta = map_get(&doc, "meta").cloned().unwrap_or(rmpv::Value::Nil);
            let comments = comments_list(&doc_dir);
            let meta_map = match &meta {
                rmpv::Value::Map(pairs) => pairs.clone(),
                _ => Vec::new(),
            };
            let get = |key: &str, default: rmpv::Value| {
                meta_map
                    .iter()
                    .find(|(k, _)| k.as_str() == Some(key))
                    .map(|(_, v)| v.clone())
                    .unwrap_or(default)
            };
            let author = match map_get(&meta, "author") {
                Some(rmpv::Value::Binary(b)) => vstr(&hex_encode(b)),
                other => other.cloned().unwrap_or(rmpv::Value::Nil),
            };
            let meta_out = rmpv::Value::Map(vec![
                (vstr("title"), get("title", vstr("Untitled"))),
                (vstr("created"), get("created", rmpv::Value::from(0u64))),
                (vstr("edited"), get("edited", rmpv::Value::from(0u64))),
                (vstr("author"), author),
                (vstr("identity"), get("identity", rmpv::Value::Nil)),
                (vstr("signature"), get("signature", rmpv::Value::Nil)),
                (vstr("format"), get("format", vstr("markdown"))),
            ]);
            res_ok_map(vec![
                (vstr("id"), rmpv::Value::from(doc_id as u64)),
                (vstr("scope"), vstr(&doc_scope)),
                (
                    vstr("content"),
                    map_get(&doc, "content")
                        .cloned()
                        .unwrap_or(rmpv::Value::Nil),
                ),
                (vstr("comments"), rmpv::Value::Array(comments)),
                (vstr("meta"), meta_out),
            ])
        }
        "comment" => {
            if !valid_scopes.contains(&scope.as_str()) {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            }
            let Some(doc_id) = doc_id else {
                return res_bytes(RES_INVALID_REQ, "No document ID specified");
            };
            let content = map_get(data, "content")
                .and_then(value_str)
                .unwrap_or_default();
            let format_type = map_get(data, "format")
                .and_then(value_str)
                .unwrap_or_else(|| "markdown".to_string());
            if content.len() > WORK_DOC_LIMIT {
                return res_bytes(RES_INVALID_REQ, "Content limit exceeded");
            }
            if content.is_empty() {
                return res_bytes(RES_INVALID_REQ, "Content is required");
            }
            let Some(doc_dir) = find_scope_path(&work_dir, &doc_id.to_string(), "all") else {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            };
            if !doc_dir.join("root").is_file() {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            }
            let comment_id = next_comment_id(&doc_dir);
            let now = rmpv::Value::F64(now_f64());
            let meta = rmpv::Value::Map(vec![
                (
                    vstr("format"),
                    vstr(if format_type == "micron" {
                        "micron"
                    } else {
                        "markdown"
                    }),
                ),
                (vstr("title"), rmpv::Value::Nil),
                (vstr("created"), now.clone()),
                (vstr("edited"), now),
                (
                    vstr("signature"),
                    map_get(data, "signature")
                        .cloned()
                        .unwrap_or(rmpv::Value::Nil),
                ),
                (vstr("author"), vbin(remote.address_hash.as_slice())),
            ]);
            let comment_path = doc_dir.join(comment_id.to_string());
            if !write_doc(&comment_path, content.trim(), &meta) {
                return res_bytes(RES_REMOTE_FAIL, "Error saving comment");
            }
            res_ok_map(vec![(vstr("id"), rmpv::Value::from(comment_id as u64))])
        }
        "create" | "propose" => {
            let title = map_get(data, "title")
                .and_then(value_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let content = map_get(data, "content")
                .and_then(value_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let format_type = map_get(data, "format")
                .and_then(value_str)
                .unwrap_or_else(|| "markdown".to_string());
            let signature = map_get(data, "signature").and_then(value_bin);
            let Some(signature) = signature else {
                return res_bytes(RES_INVALID_REQ, "No signature provided");
            };
            if signature.len() != SIG_BYTES {
                return res_bytes(RES_INVALID_REQ, "Invalid signature length");
            }
            if !validate_doc_signature(remote, &content, signature) {
                return res_bytes(RES_INVALID_REQ, "Invalid signature");
            }
            if title.len() + content.len() + format_type.len() > WORK_DOC_LIMIT {
                return res_bytes(RES_INVALID_REQ, "Content limit exceeded");
            }
            if title.is_empty() {
                return res_bytes(RES_INVALID_REQ, "Title is required");
            }
            if content.is_empty() {
                return res_bytes(RES_INVALID_REQ, "Content is required");
            }
            let scope_name = if operation == "create" {
                "active"
            } else {
                "proposed"
            };
            let scope_dir = work_dir.join(scope_name);
            let doc_id = next_doc_id(&work_dir);
            let doc_dir = scope_dir.join(doc_id.to_string());
            if std::fs::create_dir_all(&doc_dir).is_err() {
                return res_bytes(RES_REMOTE_FAIL, "Error saving document");
            }
            let now = rmpv::Value::F64(now_f64());
            let meta = rmpv::Value::Map(vec![
                (
                    vstr("format"),
                    vstr(if format_type == "micron" {
                        "micron"
                    } else {
                        "markdown"
                    }),
                ),
                (vstr("title"), vstr(&title)),
                (vstr("created"), now.clone()),
                (vstr("edited"), now),
                (vstr("author"), vbin(remote.address_hash.as_slice())),
                (vstr("signature"), vbin(signature)),
                (vstr("identity"), vbin(&remote.to_bytes())),
            ]);
            if !write_doc(&doc_dir.join("root"), &content, &meta) {
                return res_bytes(RES_REMOTE_FAIL, "Error saving document");
            }
            if operation == "propose" {
                let id_hex = hex_encode(remote.address_hash.as_slice());
                let owner = format!("i:{id_hex}\nw:{id_hex}\n");
                let allowed_path = work_dir.join(format!("{doc_id}.allowed"));
                let tmp_path = allowed_path.with_extension("tmp");
                if std::fs::write(&tmp_path, &owner).is_err()
                    || std::fs::rename(&tmp_path, &allowed_path).is_err()
                {
                    return res_bytes(RES_REMOTE_FAIL, "Error setting document ownership");
                }
            }
            res_ok_map(vec![
                (vstr("id"), rmpv::Value::from(doc_id as u64)),
                (vstr("scope"), vstr(scope_name)),
            ])
        }
        "edit" => {
            if !valid_scopes.contains(&scope.as_str()) {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            }
            let content = map_get(data, "content")
                .and_then(value_str)
                .unwrap_or_default();
            let title = map_get(data, "title")
                .and_then(value_str)
                .unwrap_or_default();
            let signature = map_get(data, "signature").and_then(value_bin);
            let Some(signature) = signature else {
                return res_bytes(RES_INVALID_REQ, "No signature provided");
            };
            if signature.len() != SIG_BYTES {
                return res_bytes(RES_INVALID_REQ, "Invalid signature length");
            }
            if !validate_doc_signature(remote, &content, signature) {
                return res_bytes(RES_INVALID_REQ, "Invalid signature");
            }
            let size = title.len() + content.len();
            if size > WORK_DOC_LIMIT {
                return res_bytes(RES_INVALID_REQ, "Content limit exceeded");
            }
            if content.is_empty() && title.is_empty() {
                return res_bytes(RES_INVALID_REQ, "No changes specified");
            }
            let Some(doc_id) = doc_id else {
                return res_bytes(RES_INVALID_REQ, "No document ID specified");
            };
            let Some(doc_dir) = find_scope_path(&work_dir, &doc_id.to_string(), "all") else {
                return res_bytes(RES_NOT_FOUND, "Not found");
            };
            let root_path = doc_dir.join("root");
            if !root_path.is_file() {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            }
            let Some(doc) = read_doc(&root_path) else {
                return res_bytes(RES_REMOTE_FAIL, "Error loading document");
            };
            let Some(meta) = map_get(&doc, "meta") else {
                return res_bytes(RES_REMOTE_FAIL, "Error loading document");
            };
            let is_author =
                map_get(meta, "author").and_then(value_bin) == Some(remote.address_hash.as_slice());
            if !is_author {
                return res_bytes(RES_DISALLOWED, "No access, not author");
            }
            let mut meta_map = match meta {
                rmpv::Value::Map(pairs) => pairs.clone(),
                _ => Vec::new(),
            };
            let mut content_out = map_get(&doc, "content")
                .and_then(value_str)
                .unwrap_or_default();
            if !title.is_empty() {
                meta_map.retain(|(k, _)| k.as_str() != Some("title"));
                meta_map.push((vstr("title"), vstr(title.trim())));
            }
            if !content.is_empty() {
                content_out = content.trim().to_string();
            }
            meta_map.retain(|(k, _)| {
                !["edited", "signature", "identity"].contains(&k.as_str().unwrap_or(""))
            });
            meta_map.push((vstr("edited"), rmpv::Value::F64(now_f64())));
            meta_map.push((vstr("signature"), vbin(signature)));
            meta_map.push((vstr("identity"), vbin(&remote.to_bytes())));
            if !write_doc(&root_path, &content_out, &rmpv::Value::Map(meta_map)) {
                return res_bytes(RES_REMOTE_FAIL, "Error saving document");
            }
            res_ok()
        }
        "delete" => {
            if !valid_scopes.contains(&scope.as_str()) {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            }
            let Some(doc_id) = doc_id else {
                return res_bytes(RES_INVALID_REQ, "No document ID specified");
            };
            let Some(doc_dir) = find_scope_path(&work_dir, &doc_id.to_string(), "all") else {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            };
            let Some(doc) = read_doc(&doc_dir.join("root")) else {
                return res_bytes(RES_REMOTE_FAIL, "Error loading document");
            };
            let is_author = map_get(&doc, "meta")
                .and_then(|m| map_get(m, "author"))
                .and_then(value_bin)
                == Some(remote.address_hash.as_slice());
            let doc_admin =
                node.resolve_doc_permission(remote, group_name, repo_name, doc_id, Perm::Admin);
            if !is_author && !doc_admin {
                return res_bytes(RES_DISALLOWED, "No access, not author");
            }
            if std::fs::remove_file(work_dir.join(format!("{doc_id}.allowed"))).is_err() {
                return res_bytes(RES_REMOTE_FAIL, "Remote error");
            }
            if std::fs::remove_dir_all(&doc_dir).is_err() {
                return res_bytes(RES_REMOTE_FAIL, "Remote error");
            }
            res_ok()
        }
        "complete" => {
            let Some(doc_id) = doc_id else {
                return res_bytes(RES_INVALID_REQ, "No document ID specified");
            };
            let active_dir = work_dir.join("active").join(doc_id.to_string());
            if !active_dir.is_dir() {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            }
            let Some(doc) = read_doc(&active_dir.join("root")) else {
                return res_bytes(RES_REMOTE_FAIL, "Error loading document");
            };
            let is_author = map_get(&doc, "meta")
                .and_then(|m| map_get(m, "author"))
                .and_then(value_bin)
                == Some(remote.address_hash.as_slice());
            let doc_admin =
                node.resolve_doc_permission(remote, group_name, repo_name, doc_id, Perm::Admin);
            if !is_author && !doc_admin {
                return res_bytes(RES_DISALLOWED, "Not allowed");
            }
            let target = work_dir.join("completed").join(doc_id.to_string());
            if std::fs::create_dir_all(work_dir.join("completed")).is_err()
                || std::fs::rename(&active_dir, &target).is_err()
            {
                return res_bytes(RES_REMOTE_FAIL, "Remote error");
            }
            res_ok_map(vec![
                (vstr("id"), rmpv::Value::from(doc_id as u64)),
                (vstr("scope"), vstr("completed")),
            ])
        }
        "activate" => {
            let Some(doc_id) = doc_id else {
                return res_bytes(RES_INVALID_REQ, "No document ID specified");
            };
            let doc_dir = ["completed", "proposed"]
                .iter()
                .map(|s| work_dir.join(s).join(doc_id.to_string()))
                .find(|d| d.is_dir());
            let Some(doc_dir) = doc_dir else {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            };
            let Some(doc) = read_doc(&doc_dir.join("root")) else {
                return res_bytes(RES_REMOTE_FAIL, "Error loading document");
            };
            let is_author = map_get(&doc, "meta")
                .and_then(|m| map_get(m, "author"))
                .and_then(value_bin)
                == Some(remote.address_hash.as_slice());
            let doc_admin =
                node.resolve_doc_permission(remote, group_name, repo_name, doc_id, Perm::Admin);
            if !is_author && !doc_admin {
                return res_bytes(RES_DISALLOWED, "Not allowed");
            }
            let target = work_dir.join("active").join(doc_id.to_string());
            if std::fs::create_dir_all(work_dir.join("active")).is_err()
                || std::fs::rename(&doc_dir, &target).is_err()
            {
                return res_bytes(RES_REMOTE_FAIL, "Remote error");
            }
            res_ok_map(vec![
                (vstr("id"), rmpv::Value::from(doc_id as u64)),
                (vstr("scope"), vstr("active")),
            ])
        }
        "perms" => {
            let Some(step) = map_get(data, "step").and_then(value_str) else {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            };
            let Some(doc_id) = doc_id else {
                return res_bytes(RES_INVALID_REQ, "No document ID specified");
            };
            let Some(doc_dir) = find_scope_path(&work_dir, &doc_id.to_string(), "all") else {
                return res_bytes(RES_NOT_FOUND, "Document not found");
            };
            let Some(doc) = read_doc(&doc_dir.join("root")) else {
                return res_bytes(RES_REMOTE_FAIL, "Error loading document");
            };
            let is_author = map_get(&doc, "meta")
                .and_then(|m| map_get(m, "author"))
                .and_then(value_bin)
                == Some(remote.address_hash.as_slice());
            let doc_admin =
                node.resolve_doc_permission(remote, group_name, repo_name, doc_id, Perm::Admin);
            let manage = interact_access && write_access;
            if !((is_author && manage) || doc_admin) {
                return res_bytes(RES_DISALLOWED, "Not allowed");
            }
            let allowed_path = work_dir.join(format!("{doc_id}.allowed"));
            match step.as_str() {
                "get" => {
                    let content = std::fs::read_to_string(&allowed_path).unwrap_or_default();
                    res_ok_map(vec![(vstr("content"), vstr(&content))])
                }
                "set" => {
                    let content = map_get(data, "content")
                        .and_then(value_str)
                        .unwrap_or_default();
                    for (line_num, line) in content.lines().enumerate() {
                        let stripped = line.trim();
                        if stripped.is_empty() || stripped.starts_with('#') {
                            continue;
                        }
                        if parse_permission_full(stripped, &node.aliases).is_none() {
                            return res_bytes(
                                RES_INVALID_REQ,
                                &format!(
                                    "Invalid permission \"{stripped}\" on line {}",
                                    line_num + 1
                                ),
                            );
                        }
                    }
                    let tmp_path = allowed_path.with_extension("tmp");
                    if std::fs::write(&tmp_path, &content).is_err()
                        || std::fs::rename(&tmp_path, &allowed_path).is_err()
                    {
                        return res_bytes(RES_REMOTE_FAIL, "Error setting permissions");
                    }
                    res_ok()
                }
                _ => res_bytes(RES_INVALID_REQ, "Invalid step"),
            }
        }
        _ => res_bytes(RES_INVALID_REQ, "Invalid request"),
    }
}

fn next_doc_id(work_dir: &Path) -> i64 {
    let scope_next = |scope: &str| -> i64 {
        let mut next = 1;
        if let Ok(entries) = std::fs::read_dir(work_dir.join(scope)) {
            for entry in entries.flatten() {
                if let Ok(id) = entry.file_name().to_string_lossy().parse::<i64>() {
                    next = next.max(id + 1);
                }
            }
        }
        next
    };
    ["active", "completed", "proposed"]
        .iter()
        .map(|s| scope_next(s))
        .max()
        .unwrap_or(1)
}

fn next_comment_id(doc_dir: &Path) -> i64 {
    let mut next = 1;
    if let Ok(entries) = std::fs::read_dir(doc_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "root" {
                continue;
            }
            if let Ok(id) = name.parse::<i64>() {
                next = next.max(id + 1);
            }
        }
    }
    next
}

// ---------------------------------------------------------------------------
// Permission management (on-disk .allowed files)
// ---------------------------------------------------------------------------

async fn handle_perms(node: &mut GitNode, remote: &Identity, data: &rmpv::Value) -> Outcome {
    let Some(operation) = map_get(data, "operation").and_then(value_str) else {
        return res_bytes(RES_INVALID_REQ, "Invalid request");
    };
    match operation.as_str() {
        "gperms" => {
            let Some(group_name) = map_get_int(data, IDX_GROUP).and_then(value_str) else {
                return res_bytes(RES_INVALID_REQ, "No group specified");
            };
            if group_name.len() > 256 || group_name.contains('/') {
                return res_bytes(RES_NOT_FOUND, "Not found");
            }
            let group_name = group_name.as_str();
            let read_access = node.resolve_group_permission(remote, group_name, Perm::Read);
            let admin_access = node.resolve_group_permission(remote, group_name, Perm::Admin);
            if !read_access {
                return res_bytes(RES_NOT_FOUND, "Not found");
            }
            if !admin_access {
                return res_bytes(RES_DISALLOWED, "Not allowed");
            }
            let Some(step) = map_get(data, "step").and_then(value_str) else {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            };
            let group_path = node.groups.get(group_name).map(|g| g.path.clone());
            let Some(group_path) = group_path else {
                return res_bytes(RES_NOT_FOUND, "Not found");
            };
            let allowed_path = PathBuf::from(format!("{}.allowed", group_path.display()));
            match step.as_str() {
                "get" => {
                    let content = std::fs::read_to_string(&allowed_path).unwrap_or_default();
                    res_ok_map(vec![(vstr("content"), vstr(&content))])
                }
                "set" => {
                    let content = map_get(data, "content")
                        .and_then(value_str)
                        .unwrap_or_default();
                    for (line_num, line) in content.lines().enumerate() {
                        let stripped = line.trim();
                        if stripped.is_empty() || stripped.starts_with('#') {
                            continue;
                        }
                        if parse_permission_full(stripped, &node.aliases).is_none() {
                            return res_bytes(
                                RES_INVALID_REQ,
                                &format!(
                                    "Invalid permission \"{stripped}\" on line {}",
                                    line_num + 1
                                ),
                            );
                        }
                    }
                    if allowed_path_is_executable(&allowed_path) {
                        return res_bytes(
                            RES_DISALLOWED,
                            "Executable permission resolvers can only be modified node-side",
                        );
                    }
                    let tmp_path = allowed_path.with_extension("tmp");
                    if std::fs::write(&tmp_path, &content).is_err()
                        || std::fs::rename(&tmp_path, &allowed_path).is_err()
                    {
                        return res_bytes(RES_REMOTE_FAIL, "Error setting permissions");
                    }
                    node.update_group_permissions(group_name);
                    res_ok()
                }
                _ => res_bytes(RES_INVALID_REQ, "Invalid step"),
            }
        }
        "rperms" => {
            let Some(repo_path) = map_get_int(data, IDX_REPOSITORY).and_then(value_str) else {
                return res_bytes(RES_INVALID_REQ, "No repository specified");
            };
            let Some((group_name, repo_name)) = parse_request_repository_path(&repo_path) else {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            };
            let read_access = node.resolve_permission(remote, group_name, repo_name, Perm::Read);
            let admin_access = node.resolve_permission(remote, group_name, repo_name, Perm::Admin);
            if !admin_access {
                return if !read_access {
                    res_bytes(RES_NOT_FOUND, "Not found")
                } else {
                    res_bytes(RES_DISALLOWED, "Not allowed")
                };
            }
            let Some(step) = map_get(data, "step").and_then(value_str) else {
                return res_bytes(RES_INVALID_REQ, "Invalid request");
            };
            let repo_dir = node
                .groups
                .get(group_name)
                .and_then(|g| g.repositories.get(repo_name))
                .map(|r| r.path.clone());
            let Some(repo_dir) = repo_dir else {
                return res_bytes(RES_NOT_FOUND, "Not found");
            };
            let allowed_path = PathBuf::from(format!("{}.allowed", repo_dir.display()));
            match step.as_str() {
                "get" => {
                    let content = std::fs::read_to_string(&allowed_path).unwrap_or_default();
                    res_ok_map(vec![(vstr("content"), vstr(&content))])
                }
                "set" => {
                    let read_access = node.resolve_group_permission(remote, group_name, Perm::Read);
                    let admin_access =
                        node.resolve_group_permission(remote, group_name, Perm::Admin);
                    if !read_access {
                        return res_bytes(RES_NOT_FOUND, "Not found");
                    }
                    if !admin_access {
                        return res_bytes(RES_DISALLOWED, "Not allowed");
                    }
                    let content = map_get(data, "content")
                        .and_then(value_str)
                        .unwrap_or_default();
                    for (line_num, line) in content.lines().enumerate() {
                        let stripped = line.trim();
                        if stripped.is_empty() || stripped.starts_with('#') {
                            continue;
                        }
                        if parse_permission_full(stripped, &node.aliases).is_none() {
                            return res_bytes(
                                RES_INVALID_REQ,
                                &format!(
                                    "Invalid permission \"{stripped}\" on line {}",
                                    line_num + 1
                                ),
                            );
                        }
                    }
                    if allowed_path_is_executable(&allowed_path) {
                        return res_bytes(
                            RES_DISALLOWED,
                            "Executable permission resolvers can only be modified node-side",
                        );
                    }
                    let tmp_path = allowed_path.with_extension("tmp");
                    if std::fs::write(&tmp_path, &content).is_err()
                        || std::fs::rename(&tmp_path, &allowed_path).is_err()
                    {
                        return res_bytes(RES_REMOTE_FAIL, "Error setting permissions");
                    }
                    node.load_repository(group_name, repo_dir).await;
                    res_ok()
                }
                _ => res_bytes(RES_INVALID_REQ, "Invalid step"),
            }
        }
        _ => res_bytes(RES_INVALID_REQ, "Invalid request"),
    }
}

// ---------------------------------------------------------------------------
// Node setup and jobs loop
// ---------------------------------------------------------------------------

/// Resolve the rngit config directory.
pub fn resolve_rngit_config_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir.to_path_buf();
    }
    if let Ok(env_dir) = std::env::var("RNGIT_CONFIG") {
        return expand_user(&env_dir);
    }
    if Path::new("/etc/rngit").is_dir() && Path::new("/etc/rngit/config").is_file() {
        return PathBuf::from("/etc/rngit");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let xdg = PathBuf::from(&home).join(".config/rngit");
    if xdg.is_dir() && xdg.join("config").is_file() {
        return PathBuf::from(&home).join(".rngit/reticulum");
    }
    PathBuf::from(&home).join(".rngit")
}

async fn load_node(config_dir: &Path) -> Result<GitNode, String> {
    let config_path = config_dir.join("config");
    let mut node = GitNode {
        identity: PrivateIdentity::new_from_rand(rand_core::OsRng),
        node_name: String::new(),
        announce_interval: 0,
        mirror_interval: 24 * 60 * 60,
        sync_check_interval: 15 * 60,
        blocked: HashSet::new(),
        aliases: Aliases::new(),
        groups: HashMap::new(),
        last_announce: 0.0,
        last_sync_check: 0.0,
    };
    if config_path.is_file() {
        let text = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("Could not read config {}: {e}", config_path.display()))?;
        let config = parse_ini(&text);
        if let Some(rngit) = config.section("rngit") {
            if let Some(name) = rngit.get("node_name") {
                node.node_name = name.to_string();
            }
            if let Some(minutes) = rngit.get_int("announce_interval") {
                node.announce_interval = (minutes.max(0) as u64) * 60;
            }
            if let Some(hours) = rngit.get_int("mirror_interval") {
                node.mirror_interval = (hours.max(0) as u64) * 60 * 60;
            }
            for hash in rngit.get_list("blocked_identities") {
                if let Some(bytes) = decode_hex(&hash) {
                    if bytes.len() == 16 {
                        let mut h = [0u8; 16];
                        h.copy_from_slice(&bytes);
                        node.blocked.insert(h);
                    }
                }
            }
        }
        if let Some(aliases) = config.section("aliases") {
            for (alias, target) in &aliases.entries {
                node.aliases.insert(alias.clone(), target.clone());
            }
        }
        if let Some(repositories) = config.section("repositories") {
            let access = config.section("access").cloned().unwrap_or_default();
            for (group_name, group_path) in &repositories.entries {
                let path = expand_user(group_path);
                node.load_repository_group(group_name, path).await;
                node.apply_config_access(group_name, &access);
            }
        }
    }
    let identity_path = config_dir.join("repositories_identity");
    let (identity, _) = load_or_create_private_identity(&identity_path).map_err(|e| {
        format!(
            "Could not load node identity {}: {e}",
            identity_path.display()
        )
    })?;
    node.identity = identity;
    Ok(node)
}

/// The `rngit.repositories` destination hash derived from the node
/// identity in `config_dir` (creates the identity file if missing).
pub fn node_destination_hash(config_dir: &Path) -> Option<AddressHash> {
    let identity_path = config_dir.join("repositories_identity");
    let (identity, _) = load_or_create_private_identity(&identity_path).ok()?;
    Some(
        reticulum::destination::SingleInputDestination::new(
            identity,
            DestinationName::new(APP_NAME, DESTINATION_ASPECT),
        )
        .desc
        .address_hash,
    )
}

/// `node -p`: prints peer identity, node identity and the repositories
/// destination.
pub async fn print_node_identities(config_dir: &Path) -> bool {
    let client_path = config_dir.join("client_identity");
    let node_path = config_dir.join("repositories_identity");
    let Some((client, _)) = load_or_create_private_identity(&client_path).ok() else {
        return false;
    };
    let Some((node, _)) = load_or_create_private_identity(&node_path).ok() else {
        return false;
    };
    let destination = reticulum::destination::SingleInputDestination::new(
        node.clone(),
        DestinationName::new(APP_NAME, DESTINATION_ASPECT),
    )
    .desc
    .address_hash;
    println!(
        "Git Peer Identity         : {}",
        prettyhexrep(client.address_hash().as_slice())
    );
    println!(
        "Repository Node Identity  : {}",
        prettyhexrep(node.address_hash().as_slice())
    );
    println!(
        "Repositories Destination  : {}",
        prettyhexrep(destination.as_slice())
    );
    true
}

pub struct NodeOptions {
    /// rngit config directory (`--config`).
    pub config_dir: PathBuf,
    /// Reticulum config directory (`--rnsconfig`).
    pub rns_config_dir: PathBuf,
    /// Optional loopback interface pair (tests).
    pub udp_loopback: Option<(u16, u16)>,
    /// Optional shutdown token; the node returns when cancelled.
    pub shutdown: Option<tokio_util::sync::CancellationToken>,
}

type NodeHandle = Arc<Mutex<GitNode>>;

/// Runs the node: registers handlers, announces, and services periodic
/// jobs until `shutdown` fires (or forever when no token was given).
/// Returns the announced destination hash once setup completes.
pub async fn serve(options: &NodeOptions) -> Result<AddressHash, String> {
    if !git_available() {
        return Err("git is not available".to_string());
    }
    let config_path = options.config_dir.join("config");
    if !config_path.is_file() {
        return Err(format!(
            "No configuration file present at {}, this node is not configured",
            config_path.display()
        ));
    }
    let node = load_node(&options.config_dir)
        .await
        .map_err(|e| format!("Could not initialise git node: {e}"))?;
    if node.groups.is_empty() {
        return Err(
            "No repository groups were available for this node. Create at least one repository group directory and configure the node"
                .to_string(),
        );
    }

    let transport = Arc::new(
        build_tool_transport(ToolTransportOptions {
            config_dir: &options.rns_config_dir,
            instance_name: "rngit",
            enable_transport: false,
            udp_loopback: options.udp_loopback,
        })
        .await,
    );

    let node_name = if node.node_name.is_empty() {
        String::new()
    } else {
        format!(" {}", node.node_name)
    };
    log::info!("git repositories{node_name} ready, waiting for requests");
    let address =
        serve_with_transport(&transport, &options.config_dir, options.shutdown.clone()).await?;
    Ok(address)
}

/// Register handlers + announce + jobs on an existing transport (used by
/// the two-instance test, which owns its transports).
pub async fn serve_with_transport(
    transport: &Arc<Transport>,
    config_dir: &Path,
    shutdown: Option<tokio_util::sync::CancellationToken>,
) -> Result<AddressHash, String> {
    let node = load_node(config_dir).await?;
    let node = Arc::new(Mutex::new(node));
    let destination = transport
        .add_destination(
            node.lock().await.identity.clone(),
            DestinationName::new(APP_NAME, DESTINATION_ASPECT),
        )
        .await;
    let address = destination.lock().await.desc.address_hash;

    for path in [
        PATH_LIST,
        PATH_FETCH,
        PATH_PUSH,
        PATH_DELETE,
        PATH_CREATE,
        PATH_FORK,
        PATH_SYNC,
        PATH_MIRROR,
        PATH_RELEASE,
        PATH_WORK,
        PATH_PERMS,
    ] {
        let node_handle = node.clone();
        let transport_handle = transport.clone();
        transport
            .register_async_request_handler(&address, path, move |ctx| {
                let node = node_handle.clone();
                let transport = transport_handle.clone();
                async move { dispatch_request(node, transport, path, ctx).await }
            })
            .await;
    }

    transport.send_announce(&destination, None).await;
    node.lock().await.last_announce = now_f64();

    let job_node = node.clone();
    let job_transport = transport.clone();
    tokio::spawn(async move {
        node_jobs(job_node, job_transport, destination, shutdown).await;
    });

    Ok(address)
}

async fn dispatch_request(
    node: NodeHandle,
    transport: Arc<Transport>,
    path: &str,
    ctx: RequestContext,
) -> Option<Vec<u8>> {
    let Some((remote, data)) = identified_map(&ctx) else {
        return Some(msgpack_bin(&invalid_req_bytes()));
    };
    let outcome = {
        let mut node = node.lock().await;
        match path {
            PATH_LIST => handle_list(&mut node, &remote, &data).await,
            PATH_FETCH => handle_fetch(&mut node, &remote, &data).await,
            PATH_PUSH => handle_push(&mut node, &remote, &data).await,
            PATH_DELETE => handle_delete(&mut node, &remote, &data).await,
            PATH_CREATE => handle_create(&mut node, &remote, &data).await,
            PATH_FORK => clone_repository(&mut node, &remote, &data, "fork").await,
            PATH_MIRROR => clone_repository(&mut node, &remote, &data, "mirror").await,
            PATH_SYNC => handle_sync(&mut node, &remote, &data).await,
            PATH_RELEASE => handle_release(&mut node, &remote, &data).await,
            PATH_WORK => handle_work(&mut node, &remote, &data).await,
            PATH_PERMS => handle_perms(&mut node, &remote, &data).await,
            _ => return Some(msgpack_bin(&invalid_req_bytes())),
        }
    };
    match outcome {
        Outcome::Bytes(payload) => Some(msgpack_bin(&payload)),
        Outcome::File { data, metadata } => {
            if let Some(link) = transport.find_in_link(&ctx.link_id).await {
                let options = ResourceOptions {
                    metadata: Some(rmpv_to_bytes(&metadata)),
                    request_id: Some(ctx.request_id),
                    is_response: true,
                    auto_compress: true,
                    ..Default::default()
                };
                if let Err(err) = transport
                    .send_resource_with_options(&link, data, options)
                    .await
                {
                    log::error!("rngit: could not send file response: {err:?}");
                }
            }
            None
        }
    }
}

fn invalid_req_bytes() -> Vec<u8> {
    let mut payload = vec![RES_INVALID_REQ];
    payload.extend_from_slice(b"Invalid request");
    payload
}

/// Periodic node jobs: re-announce, mirror/fork sync checks, dynamic
/// permission refresh.
async fn node_jobs(
    node: NodeHandle,
    transport: Arc<Transport>,
    destination: Arc<Mutex<reticulum::destination::SingleInputDestination>>,
    shutdown: Option<tokio_util::sync::CancellationToken>,
) {
    let tick = Duration::from_secs(5);
    loop {
        if let Some(token) = &shutdown {
            if token.is_cancelled() {
                break;
            }
        }
        tokio::time::sleep(tick).await;
        let now = now_f64();
        let (
            announce_interval,
            last_announce,
            sync_check_interval,
            mirror_interval,
            last_sync_check,
        ) = {
            let node = node.lock().await;
            (
                node.announce_interval,
                node.last_announce,
                node.sync_check_interval,
                node.mirror_interval,
                node.last_sync_check,
            )
        };
        if announce_interval > 0 && now > last_announce + announce_interval as f64 {
            transport.send_announce(&destination, None).await;
            node.lock().await.last_announce = now;
        }
        if now > last_sync_check + sync_check_interval as f64 {
            let mut node = node.lock().await;
            node.last_sync_check = now;
            if node.groups.values().any(|group| group.dynamic_perms) {
                let group_names: Vec<String> = node
                    .groups
                    .iter()
                    .filter(|(_, group)| group.dynamic_perms)
                    .map(|(name, _)| name.clone())
                    .collect();
                for name in group_names {
                    node.update_group_permissions(&name);
                }
            }
            // Mirror sync check
            let mut syncs: Vec<(PathBuf, String)> = Vec::new();
            if mirror_interval > 0 {
                for group in node.groups.values() {
                    for repo in group.repositories.values() {
                        if let Some(source) = repo.mirror.clone() {
                            let synced = mirror_synced(&repo.path).await;
                            if (now - synced as f64) > mirror_interval as f64 {
                                syncs.push((repo.path.clone(), source));
                            }
                        }
                    }
                }
            }
            drop(node);
            for (path, source) in syncs {
                if sync_repository(&path, &source).await {
                    set_mirror_synced(&path).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client (link + request machinery to talk to a node)
// ---------------------------------------------------------------------------

/// Options controlling how a client attaches to Reticulum.
pub struct ClientOptions {
    /// rngit config directory (`--config` / `RNGIT_CONFIG`).
    pub rngit_config_dir: PathBuf,
    /// Reticulum config directory (`--rnsconfig` / `RNS_CONFIG` /
    /// `RETICULUM_CONFIG_DIR`).
    pub rns_config_dir: PathBuf,
    /// `-i/--identity` path for client operations (else `client_identity`
    /// inside the rngit config dir).
    pub identity_path: Option<PathBuf>,
    /// Optional loopback interface pair for tests.
    pub udp_loopback: Option<(u16, u16)>,
    pub path_timeout: Duration,
    pub link_timeout: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            rngit_config_dir: resolve_rngit_config_dir(None),
            rns_config_dir: resolve_config_dir(None),
            identity_path: None,
            udp_loopback: None,
            path_timeout: PATH_TIMEOUT,
            link_timeout: LINK_TIMEOUT,
        }
    }
}

struct ClientConfig {
    ref_batch_size: usize,
    destination_aliases: Aliases,
}

const CLIENT_CONFIG_TEMPLATE: &str =
    "# This is the default Reticulum Git client configuration file.\n\
     # You should make any changes to the configuration in a secondary,\n\
     # user-specific configuration file located at:\n\
     # ~/.rngit/client_config\n\
     \n\
     [client]\n\
     # Size of ref batches to request when fetching.\n\
     # ref_batch_size = 25\n\
     \n\
     [aliases]\n\
     # myrepos = 9ba1d24c5c6c9bd5f9a5f1e1be8c3a2f\n";

fn load_client_config(config_dir: &Path) -> ClientConfig {
    let mut config = ClientConfig {
        ref_batch_size: REF_BATCH_SIZE,
        destination_aliases: Aliases::new(),
    };
    let config_path = config_dir.join("client_config");
    if !config_path.is_file() {
        let _ = std::fs::create_dir_all(config_dir);
        let _ = std::fs::write(&config_path, CLIENT_CONFIG_TEMPLATE);
    }
    if let Ok(text) = std::fs::read_to_string(&config_path) {
        let ini = parse_ini(&text);
        let size = ini
            .section("client")
            .and_then(|s| s.get_int("ref_batch_size"))
            .or_else(|| {
                ini.section("rngit")
                    .and_then(|s| s.get_int("ref_batch_size"))
            });
        if let Some(size) = size {
            config.ref_batch_size = size.clamp(0, 1024) as usize;
        }
        if let Some(aliases) = ini.section("aliases") {
            for (alias, target) in &aliases.entries {
                config
                    .destination_aliases
                    .insert(alias.clone(), target.clone());
            }
        }
    }
    config
}

fn parse_remote_url(
    url: &str,
    aliases: &Aliases,
    want_repo: bool,
) -> Result<(AddressHash, Option<String>, Option<String>), String> {
    if url.trim().is_empty() {
        return Err("Invalid remote URL".to_string());
    }
    let mut url = url.trim().to_string();
    if url.starts_with(PROTO_SPEC) {
        url = url[PROTO_SPEC.len()..].to_string();
    }
    let components: Vec<&str> = url.split('/').collect();
    let destination = resolve_alias(aliases, components[0], false);
    if destination.len() != 32 {
        return Err("Invalid remote URL".to_string());
    }
    let Some(hash_bytes) = decode_hex(destination) else {
        return Err("Invalid remote URL".to_string());
    };
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&hash_bytes[..16]);
    let group = components.get(1).map(|s| s.to_string());
    let repo = components.get(2).map(|s| s.to_string());
    if want_repo && (components.len() != 3 || group.is_none() || repo.is_none()) {
        return Err("Invalid remote URL".to_string());
    }
    Ok((AddressHash::new(hash), group, repo))
}

/// A live link to a remote rngit node with request helpers.
pub struct RemoteClient {
    pub transport: Arc<Transport>,
    pub link: Arc<Mutex<Link>>,
    pub identity: PrivateIdentity,
    pub ref_batch_size: usize,
    pub remote_refs: HashMap<String, String>,
    /// Whether git asked for progress output (`option progress true`).
    pub progress_enabled: bool,
}

/// A response from a request: payload bytes plus decoded metadata (file
/// responses).
pub struct RemoteResponse {
    pub data: Vec<u8>,
    pub metadata: Option<rmpv::Value>,
}

impl RemoteClient {
    /// Await path, recall destination, link + identify.
    pub async fn connect(options: &ClientOptions, remote: &str) -> Result<Self, String> {
        let client_config = load_client_config(&options.rngit_config_dir);
        let (destination_hash, _, _) =
            parse_remote_url(remote, &client_config.destination_aliases, false)?;
        log::info!("Establishing link to remote...");
        let transport = Arc::new(
            build_tool_transport(ToolTransportOptions {
                config_dir: &options.rns_config_dir,
                instance_name: "rngit",
                enable_transport: false,
                udp_loopback: options.udp_loopback,
            })
            .await,
        );

        let identity_path = match &options.identity_path {
            Some(path) => expand_user(&path.to_string_lossy()),
            None => options.rngit_config_dir.join("client_identity"),
        };
        let (identity, _) = load_or_create_private_identity(&identity_path).map_err(|e| {
            format!(
                "Could not load client identity {}: {e}",
                identity_path.display()
            )
        })?;

        let desc = crate::rnpath::wait_for_destination(
            &transport,
            &destination_hash,
            options.path_timeout,
        )
        .await
        .ok_or_else(|| "Link establishment failed (path not found)".to_string())?;

        let mut events = transport.out_link_events();
        let link = transport.link(desc).await;
        let link_id = *link.lock().await.id();
        let deadline = tokio::time::Instant::now() + options.link_timeout;
        loop {
            if link.lock().await.status() == LinkStatus::Active {
                break;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("Link establishment failed".to_string());
            }
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(LinkEventData {
                    id,
                    event: LinkEvent::Activated,
                    ..
                })) if id == link_id => break,
                Ok(Ok(LinkEventData {
                    id,
                    event: LinkEvent::Closed,
                    ..
                })) if id == link_id => {
                    return Err("Link establishment failed".to_string());
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => continue,
                Err(_) => {
                    if link.lock().await.status() == LinkStatus::Active {
                        break;
                    }
                    return Err("Link establishment failed".to_string());
                }
            }
        }

        let packet = link
            .lock()
            .await
            .identify(&identity)
            .map_err(|e| format!("Could not identify on link: {e:?}"))?;
        transport.send_packet(packet).await;

        Ok(Self {
            transport,
            link,
            identity,
            ref_batch_size: client_config.ref_batch_size,
            remote_refs: HashMap::new(),
            progress_enabled: false,
        })
    }

    pub async fn close(&self) {
        let link_id = *self.link.lock().await.id();
        let _ = self.transport.link_close(link_id).await;
    }

    /// Issue a link request and wait for the matching response (packet or
    /// resource-carried).
    pub async fn send_request(
        &self,
        path: &str,
        data: rmpv::Value,
        timeout: Duration,
    ) -> Result<RemoteResponse, String> {
        let mut events = self.transport.request_events().await;
        let packed = rmpv_to_bytes(&data);
        let request_id = self
            .transport
            .request(&self.link, path, &packed)
            .await
            .map_err(|e| format!("Request failed: {e:?}"))?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("Request timed out".to_string());
            }
            let event = match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(event)) => event,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(_)) => return Err("Request failed".to_string()),
                Err(_) => return Err("Request timed out".to_string()),
            };
            match event.event {
                RequestEvent::Response {
                    request_id: rid,
                    data,
                    metadata,
                } if rid == request_id => {
                    let metadata = metadata.and_then(|m| unpack_value(&m));
                    return Ok(RemoteResponse { data, metadata });
                }
                RequestEvent::Failed { request_id: rid } if rid == request_id => {
                    return Err("Request failed".to_string());
                }
                _ => continue,
            }
        }
    }

    /// `{"0": repo_path, "for_push": bool}` → ref text.
    pub async fn list_refs(&mut self, repo_path: &str, for_push: bool) -> Result<String, String> {
        let request = rmpv::Value::Map(vec![
            (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
            (vstr("for_push"), rmpv::Value::Boolean(for_push)),
        ]);
        let response = self
            .send_request(PATH_LIST, request, Duration::from_secs(30))
            .await?;
        if response.data.is_empty() {
            return Err("Remote error: Unknown error".to_string());
        }
        let status = response.data[0];
        if status != RES_OK {
            let msg = String::from_utf8_lossy(&response.data[1..]).to_string();
            return Err(format!("Remote error: {msg}"));
        }
        let refs = String::from_utf8_lossy(&response.data[1..]).to_string();
        self.remote_refs.clear();
        for line in refs.lines() {
            let Some((sha, name)) = line.split_once(' ') else {
                continue;
            };
            if name == "HEAD" {
                continue;
            }
            self.remote_refs.insert(name.to_string(), sha.to_string());
        }
        Ok(refs)
    }

    /// Fetch refs as a bundle and unbundle into `work_dir` (a git
    /// repository).
    pub async fn fetch_refs(
        &mut self,
        refs: &[(String, String)],
        repo_path: &str,
        work_dir: &Path,
        timeout: Duration,
    ) -> Result<(), String> {
        // Have-shas: remote ref targets already present locally.
        let mut have_shas: Vec<String> = Vec::new();
        for sha in self.remote_refs.values() {
            if have_shas.contains(sha) {
                continue;
            }
            let exists = tokio::process::Command::new("git")
                .args(["cat-file", "-t", sha])
                .current_dir(work_dir)
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if exists {
                have_shas.push(sha.clone());
            }
        }
        let batches: Vec<&[(String, String)]> = refs.chunks(self.ref_batch_size).collect();
        for batch in batches {
            let mut refs_list: Vec<rmpv::Value> = Vec::new();
            for (sha, reference) in batch.iter() {
                let mut entry = vec![(vstr("sha"), vstr(sha)), (vstr("ref"), vstr(reference))];
                let local_sha = tokio::process::Command::new("git")
                    .args(["rev-parse", reference])
                    .current_dir(work_dir)
                    .output()
                    .await
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                if let Some(local) = local_sha {
                    if local != *sha && san_sha(&local).is_some() {
                        entry.push((vstr("have"), vstr(&local)));
                    }
                }
                refs_list.push(rmpv::Value::Map(entry));
            }
            let mut request = vec![
                (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
                (vstr("refs"), rmpv::Value::Array(refs_list)),
            ];
            if !have_shas.is_empty() {
                request.push((
                    vstr("have"),
                    rmpv::Value::Array(have_shas.iter().map(|s| vstr(s)).collect()),
                ));
            }
            let response = self
                .send_request(PATH_FETCH, rmpv::Value::Map(request), timeout)
                .await?;
            match response.metadata {
                None => {
                    if response.data.is_empty() {
                        return Err("Remote error: Unknown error".to_string());
                    }
                    match response.data[0] {
                        RES_OK => { /* empty bundle */ }
                        _ => {
                            let msg = String::from_utf8_lossy(&response.data[1..]).to_string();
                            return Err(format!("Remote error: {msg}"));
                        }
                    }
                }
                Some(metadata) => {
                    let code = map_get_int(&metadata, IDX_RESULT_CODE)
                        .and_then(value_i64)
                        .unwrap_or(-1);
                    if code != RES_OK as i64 {
                        return Err("Remote error: Unknown error".to_string());
                    }
                    let bundle_path = temp_path("fetch", ".bundle");
                    std::fs::write(&bundle_path, &response.data)
                        .map_err(|e| format!("Could not write bundle: {e}"))?;
                    let bundle_str = bundle_path.to_string_lossy().to_string();
                    let verified = tokio::process::Command::new("git")
                        .args(["bundle", "verify", "-q", &bundle_str])
                        .current_dir(work_dir)
                        .output()
                        .await
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    if !verified {
                        let _ = std::fs::remove_file(&bundle_path);
                        return Err("Bundle verification failed for batch".to_string());
                    }
                    let unbundled = tokio::process::Command::new("git")
                        .args(["bundle", "unbundle", &bundle_str])
                        .current_dir(work_dir)
                        .output()
                        .await
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    let _ = std::fs::remove_file(&bundle_path);
                    if !unbundled {
                        return Err(
                            "Bundle unbundle failed for batch: Non-zero return code".to_string()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Push or delete refspecs over the network.
    /// Each entry is `(local_ref, remote_ref, force)`; an empty
    /// `local_ref` deletes the remote ref.
    pub async fn push_refs(
        &mut self,
        specs: &[(String, String, bool)],
        repo_path: &str,
        work_dir: &Path,
        timeout: Duration,
    ) -> Vec<(String, Result<(), String>)> {
        let mut results = Vec::new();
        for (local_ref, remote_ref, force) in specs {
            if local_ref.is_empty() {
                let request = rmpv::Value::Map(vec![
                    (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
                    (vstr("ref"), vstr(remote_ref)),
                ]);
                let result = match self.send_request(PATH_DELETE, request, timeout).await {
                    Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
                        Ok(())
                    }
                    Ok(response) => Err(format!(
                        "Remote error: {}",
                        String::from_utf8_lossy(&response.data[1..])
                    )),
                    Err(err) => Err(err),
                };
                results.push((remote_ref.clone(), result));
                continue;
            }
            let local_sha = tokio::process::Command::new("git")
                .args(["rev-parse", local_ref])
                .current_dir(work_dir)
                .output()
                .await
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
            let Some(local_sha) = local_sha else {
                results.push((
                    remote_ref.clone(),
                    Err(format!("Could not resolve local ref {local_ref}")),
                ));
                continue;
            };
            let bundle_path = temp_path("push", ".bundle");
            let mut args = vec![
                "bundle".to_string(),
                "create".to_string(),
                bundle_path.to_string_lossy().to_string(),
                local_ref.clone(),
            ];
            // Exclude every remote SHA the local repository already has so
            // the bundle only carries objects the remote is missing.
            for sha in self.remote_refs.values() {
                let exists = tokio::process::Command::new("git")
                    .args(["cat-file", "-t", sha])
                    .current_dir(work_dir)
                    .output()
                    .await
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if exists {
                    args.push(format!("^{sha}"));
                }
            }
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let created = tokio::process::Command::new("git")
                .args(&arg_refs)
                .current_dir(work_dir)
                .output()
                .await
                .ok();
            // All objects reachable from local_ref already exist on the
            // remote: send a direct update_ref operation, no bundle upload.
            let bundle_empty = created
                .as_ref()
                .map(|o| {
                    !o.status.success()
                        && String::from_utf8_lossy(&o.stderr)
                            .to_lowercase()
                            .contains("empty bundle")
                })
                .unwrap_or(false);
            let bundle_created =
                matches!(&created, Some(o) if o.status.success()) && bundle_path.is_file();
            let result = if bundle_empty || bundle_created {
                let bundle = if bundle_created {
                    std::fs::read(&bundle_path).unwrap_or_default()
                } else {
                    Vec::new()
                };
                if bundle.is_empty() {
                    let operations = rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                        (vstr("action"), vstr("update_ref")),
                        (vstr("ref"), vstr(remote_ref)),
                        (vstr("sha"), vstr(&local_sha)),
                        (vstr("force"), rmpv::Value::Boolean(*force)),
                    ])]);
                    let request = rmpv::Value::Map(vec![
                        (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
                        (vstr("operations"), operations),
                    ]);
                    match self.send_request(PATH_PUSH, request, timeout).await {
                        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
                            Ok(())
                        }
                        Ok(response) => Err(format!(
                            "Remote error: {}",
                            String::from_utf8_lossy(&response.data[1..])
                        )),
                        Err(err) => Err(err),
                    }
                } else {
                    let request = rmpv::Value::Map(vec![
                        (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
                        (vstr("local_ref"), vstr(local_ref)),
                        (vstr("remote_ref"), vstr(remote_ref)),
                        (vstr("force"), rmpv::Value::Boolean(*force)),
                        (vstr("bundle"), vbin(&bundle)),
                    ]);
                    match self.send_request(PATH_PUSH, request, timeout).await {
                        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
                            Ok(())
                        }
                        Ok(response) => Err(format!(
                            "Remote error: {}",
                            String::from_utf8_lossy(&response.data[1..])
                        )),
                        Err(err) => Err(err),
                    }
                }
            } else {
                Err("Could not create push bundle".to_string())
            };
            let _ = std::fs::remove_file(&bundle_path);
            results.push((remote_ref.clone(), result));
        }
        results
    }

    /// `{"0": repo_path}` → PATH_CREATE.
    pub async fn create_repository(&self, repo_path: &str) -> Result<(), String> {
        let request = rmpv::Value::Map(vec![(rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path))]);
        let response = self
            .send_request(PATH_CREATE, request, Duration::from_secs(30))
            .await?;
        if response.data.is_empty() {
            return Err("Remote error: Unknown error".to_string());
        }
        if response.data[0] != RES_OK {
            return Err(format!(
                "Remote error: {}",
                String::from_utf8_lossy(&response.data[1..])
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signed messages (RSG — pack/unpack/verify shared with `rnid`)
// ---------------------------------------------------------------------------

/// `validate_rsg` -> Some((signed view, signing identity hash hex)).
fn validate_rsg(
    rsg: &[u8],
    message: &[u8],
    required_signer: Option<&[u8; 16]>,
) -> Option<(crate::rnid::SignedView, String)> {
    let required = required_signer.map(|hash| AddressHash::new(*hash));
    verify_rsg(rsg, message, required.as_ref())
        .map(|(view, identity)| (view, hex_encode(identity.address_hash.as_slice())))
}

/// -> Ok(()) or Err(reason).
fn check_release_rsm_structure(meta: &rmpv::Value) -> Result<(), String> {
    let name = map_get(meta, "name").and_then(value_str);
    let version = map_get(meta, "version").and_then(value_str);
    let origin = map_get(meta, "origin").and_then(value_bin);
    let path = map_get(meta, "path").and_then(value_str);
    if name.is_none() || version.is_none() {
        return Err("Incomplete package data in manifest".to_string());
    }
    if origin.is_none() || path.is_none() {
        return Err("Incomplete release origin data in manifest".to_string());
    }
    let name = name.unwrap();
    let version = version.unwrap();
    if name.contains('/') || version.contains('/') {
        return Err("Invalid data in release manifest".to_string());
    }
    let origin = origin.unwrap();
    if origin.len() != 16 {
        return Err("Invalid origin hash length in manifest".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Editor helpers (permissions, work documents, release notes)
// ---------------------------------------------------------------------------

fn pick_editor() -> Option<String> {
    if let Ok(editor) = std::env::var("EDITOR") {
        if !editor.is_empty() {
            return Some(editor);
        }
    }
    for fallback in ["nano", "vim", "vi"] {
        let ok = std::process::Command::new("which")
            .arg(fallback)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(fallback.to_string());
        }
    }
    None
}

fn edit_with_editor(initial: &str, suffix: &str) -> Option<String> {
    let editor = pick_editor()?;
    let tmp = temp_path("edit", suffix);
    if std::fs::write(&tmp, initial).is_err() {
        return None;
    }
    let status = std::process::Command::new(&editor).arg(&tmp).status();
    let edited = std::fs::read_to_string(&tmp).ok();
    let _ = std::fs::remove_file(&tmp);
    match status {
        Ok(status) if status.success() => edited,
        _ => None,
    }
}

fn edit_release_notes(tag: &str) -> Option<String> {
    let template = RELEASE_NOTES_TEMPLATE.replace("{TAG}", tag);
    let content = edit_with_editor(&template, ".md")?;
    let notes: String = content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    if notes.is_empty() {
        None
    } else {
        Some(notes)
    }
}

fn edit_permissions(content: &str) -> Option<String> {
    let template = if content.is_empty() {
        PERMISSIONS_TEMPLATE
    } else {
        content
    };
    edit_with_editor(template, ".txt")
}

fn edit_work_content(title: &str, content: &str, is_comment: bool) -> Option<String> {
    let _ = title;
    let template = if is_comment {
        COMMENT_TEMPLATE
    } else if content.is_empty() {
        CREATE_DOC_TEMPLATE
    } else {
        content
    };
    let edited = edit_with_editor(template, ".md")?;
    let result: String = edited
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.starts_with(COMMENT_TEMPLATE) && !line.starts_with(CREATE_DOC_TEMPLATE)
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// Client operations
// ---------------------------------------------------------------------------

struct OperationOutput {
    code: i32,
    /// Lines written to stdout.
    out: Vec<String>,
}

impl OperationOutput {
    fn ok(lines: impl IntoIterator<Item = String>) -> Self {
        Self {
            code: 0,
            out: lines.into_iter().collect(),
        }
    }

    fn abort(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            out: vec![message.into()],
        }
    }
}

fn res_error(response: &RemoteResponse) -> String {
    if response.data.is_empty() {
        return "No response from remote".to_string();
    }
    format!(
        "Remote error: {}",
        String::from_utf8_lossy(&response.data[1..])
    )
}

fn repo_path_of(remote: &str, config_dir: &Path) -> Result<String, String> {
    let aliases = load_client_config(config_dir).destination_aliases;
    let (_, group, repo) = parse_remote_url(remote, &aliases, true)?;
    Ok(format!(
        "{}/{}",
        group.unwrap_or_default(),
        repo.unwrap_or_default()
    ))
}

/// `rngit create <rns://hash/group/repo>`
async fn op_create(client: &RemoteClient, remote: &str, config_dir: &Path) -> OperationOutput {
    let repo_path = match repo_path_of(remote, config_dir) {
        Ok(path) => path,
        Err(err) => return OperationOutput::abort(err),
    };
    match client.create_repository(&repo_path).await {
        Ok(()) => OperationOutput::ok([format!("Repository created at {remote}")]),
        Err(err) => OperationOutput::abort(format!("Could not create repository: {err}")),
    }
}

/// `rngit fork|mirror <source> <rns://...>`
async fn op_clone(
    client: &RemoteClient,
    remote: &str,
    source: &str,
    path: &str,
    config_dir: &Path,
) -> OperationOutput {
    let repo_path = match repo_path_of(remote, config_dir) {
        Ok(p) => p,
        Err(err) => return OperationOutput::abort(err),
    };
    let request = rmpv::Value::Map(vec![
        (rmpv::Value::from(IDX_REPOSITORY), vstr(&repo_path)),
        (vstr("source"), vstr(source)),
    ]);
    match client
        .send_request(path, request, Duration::from_secs(120))
        .await
    {
        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
            OperationOutput::ok(["Repository cloned".to_string()])
        }
        Ok(response) => OperationOutput::abort(res_error(&response)),
        Err(err) => OperationOutput::abort(err),
    }
}

/// `rngit sync <rns://...>`
async fn op_sync(client: &RemoteClient, remote: &str, config_dir: &Path) -> OperationOutput {
    let repo_path = match repo_path_of(remote, config_dir) {
        Ok(p) => p,
        Err(err) => return OperationOutput::abort(err),
    };
    let request = rmpv::Value::Map(vec![(rmpv::Value::from(IDX_REPOSITORY), vstr(&repo_path))]);
    match client
        .send_request(PATH_SYNC, request, Duration::from_secs(120))
        .await
    {
        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
            OperationOutput::ok(["Repository synced".to_string()])
        }
        Ok(response) => OperationOutput::abort(res_error(&response)),
        Err(err) => OperationOutput::abort(err),
    }
}

fn fmt_time(ts: f64, format: &str) -> String {
    let secs = ts as i64;
    let days = secs.div_euclid(86400);
    let secs_of_day = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format
        .replace("%Y", &format!("{y:04}"))
        .replace("%m", &format!("{m:02}"))
        .replace("%d", &format!("{d:02}"))
        .replace("%H", &format!("{hh:02}"))
        .replace("%M", &format!("{mm:02}"))
        .replace("%S", &format!("{ss:02}"))
}

/// Days-from-civil inverse (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `rngit release list|view|latest|delete|fetch|create|publish|thanks`
#[allow(clippy::too_many_arguments)]
async fn op_release(
    client: &RemoteClient,
    remote: &str,
    config_dir: &Path,
    operation: &str,
    target: Option<&str>,
    signer: Option<&str>,
    name: Option<&str>,
    no_upload: bool,
    offline: bool,
) -> OperationOutput {
    let repo_path = match repo_path_of(remote, config_dir) {
        Ok(p) => p,
        Err(err) => return OperationOutput::abort(err),
    };
    let request_for = |op: &str, extra: Vec<(rmpv::Value, rmpv::Value)>| {
        let mut pairs = vec![
            (rmpv::Value::from(IDX_REPOSITORY), vstr(&repo_path)),
            (vstr("operation"), vstr(op)),
        ];
        pairs.extend(extra);
        rmpv::Value::Map(pairs)
    };
    match operation {
        "list" => {
            let response = match client
                .send_request(
                    PATH_RELEASE,
                    request_for("list", vec![]),
                    Duration::from_secs(120),
                )
                .await
            {
                Ok(r) => r,
                Err(err) => return OperationOutput::abort(err),
            };
            if response.data.is_empty() || response.data[0] != RES_OK {
                return OperationOutput::abort(res_error(&response));
            }
            let unpacked = if response.data.len() > 1 {
                match unpack_value(&response.data[1..]) {
                    Some(v) => v,
                    None => {
                        return OperationOutput::abort("Invalid release data format from remote")
                    }
                }
            } else {
                rmpv::Value::Array(vec![])
            };
            let (releases, latest) = match &unpacked {
                rmpv::Value::Array(_) => (unpacked.clone(), rmpv::Value::Nil),
                rmpv::Value::Map(_) => (
                    map_get(&unpacked, "releases")
                        .cloned()
                        .unwrap_or(rmpv::Value::Array(vec![])),
                    map_get(&unpacked, "latest")
                        .cloned()
                        .unwrap_or(rmpv::Value::Nil),
                ),
                _ => return OperationOutput::abort("Invalid release data format from remote"),
            };
            let mut out = Vec::new();
            let mut any = false;
            if let rmpv::Value::Array(list) = releases {
                if list.is_empty() {
                    out.push("No releases for this repository".to_string());
                } else {
                    out.push(format!(
                        "{:<10} {:<10} {:<17} {:<5} Notes",
                        "Tag", "Status", "Created", "Objs"
                    ));
                    out.push("-".repeat(80));
                    for rel in &list {
                        any = true;
                        let tag = map_get(rel, "tag").and_then(value_str).unwrap_or_default();
                        let status = map_get(rel, "status")
                            .and_then(value_str)
                            .unwrap_or_default();
                        let created = map_get(rel, "created").and_then(value_f64).unwrap_or(0.0);
                        let created_str = if created > 0.0 {
                            fmt_time(created, "%Y-%m-%d %H:%M")
                        } else {
                            "unknown".to_string()
                        };
                        let artifacts = map_get(rel, "artifacts").and_then(value_i64).unwrap_or(0);
                        let preview = map_get(rel, "preview")
                            .and_then(value_str)
                            .unwrap_or_default();
                        let preview = preview.lines().next().unwrap_or("");
                        out.push(format!(
                            "{:<10} {:<10} {:<17} {:<5} {}",
                            &tag[..tag.len().min(10)],
                            &status[..status.len().min(9)],
                            created_str,
                            artifacts,
                            &preview[..preview.len().min(34)]
                        ));
                    }
                    if let Some(latest) = latest.as_str() {
                        out.push(format!("\nThe latest release is: {latest}"));
                    }
                }
            }
            let _ = any;
            OperationOutput::ok(out)
        }
        "view" => {
            let Some(target) = target else {
                return OperationOutput::abort("No target specified");
            };
            let response = match client
                .send_request(
                    PATH_RELEASE,
                    request_for("view", vec![(vstr("tag"), vstr(target))]),
                    Duration::from_secs(300),
                )
                .await
            {
                Ok(r) => r,
                Err(err) => return OperationOutput::abort(err),
            };
            if response.data.is_empty() || response.data[0] != RES_OK {
                return OperationOutput::abort(res_error(&response));
            }
            let Some(release) = (response.data.len() > 1)
                .then(|| unpack_value(&response.data[1..]))
                .flatten()
            else {
                return OperationOutput::abort("Empty response from remote");
            };
            let mut out = Vec::new();
            out.push(format!(
                "Release : {}",
                map_get(&release, "tag")
                    .and_then(value_str)
                    .unwrap_or_else(|| target.to_string())
            ));
            out.push(format!(
                "Status  : {}",
                map_get(&release, "status")
                    .and_then(value_str)
                    .unwrap_or_else(|| "unknown".into())
            ));
            if let Some(created) = map_get(&release, "created").and_then(value_f64) {
                if created > 0.0 {
                    out.push(format!(
                        "Created : {}",
                        fmt_time(created, "%Y-%m-%d %H:%M:%S")
                    ));
                }
            }
            out.push(format!(
                "Thanks  : {}",
                map_get(&release, "thanks").and_then(value_i64).unwrap_or(0)
            ));
            let notes = map_get(&release, "notes")
                .and_then(value_str)
                .unwrap_or_default();
            if !notes.is_empty() {
                out.push("\nRelease Notes".to_string());
                out.push("=============\n".to_string());
                out.push(notes);
            }
            if let Some(artifacts) = map_get(&release, "artifacts").and_then(|v| v.as_array()) {
                if !artifacts.is_empty() {
                    let header = format!("Artifacts ({})", artifacts.len());
                    out.push(format!("\n{header}"));
                    out.push("=".repeat(header.len()));
                    for artifact in artifacts {
                        let name = map_get(artifact, "name")
                            .and_then(value_str)
                            .unwrap_or_default();
                        let size = map_get(artifact, "size").and_then(value_i64).unwrap_or(0);
                        out.push(format!(" - {name} ({size} B)"));
                    }
                }
            }
            out.push(String::new());
            OperationOutput::ok(out)
        }
        "latest" => {
            let Some(target) = target else {
                return OperationOutput::abort("No target specified");
            };
            print!("Are you sure you want to set {target} as the latest release? [y/N]: ");
            {
                use std::io::Write;
                let _ = std::io::stdout().flush();
                let mut confirm = String::new();
                let _ = std::io::stdin().read_line(&mut confirm);
                if confirm.trim().to_lowercase() != "y" {
                    return OperationOutput::ok(["Update cancelled".to_string()]);
                }
            }
            let response = match client
                .send_request(
                    PATH_RELEASE,
                    request_for("latest", vec![(vstr("tag"), vstr(target))]),
                    Duration::from_secs(120),
                )
                .await
            {
                Ok(r) => r,
                Err(err) => return OperationOutput::abort(err),
            };
            if response.data.is_empty() || response.data[0] != RES_OK {
                return OperationOutput::abort(res_error(&response));
            }
            OperationOutput::ok([format!("Release {target} set as latest")])
        }
        "delete" => {
            let Some(target) = target else {
                return OperationOutput::abort("No target specified");
            };
            print!("Are you sure you want to delete release {target}? [y/N]: ");
            {
                use std::io::Write;
                let _ = std::io::stdout().flush();
                let mut confirm = String::new();
                let _ = std::io::stdin().read_line(&mut confirm);
                if confirm.trim().to_lowercase() != "y" {
                    return OperationOutput::ok(["Deletion cancelled".to_string()]);
                }
            }
            let response = match client
                .send_request(
                    PATH_RELEASE,
                    request_for("delete", vec![(vstr("tag"), vstr(target))]),
                    Duration::from_secs(60),
                )
                .await
            {
                Ok(r) => r,
                Err(err) => return OperationOutput::abort(err),
            };
            if response.data.is_empty() || response.data[0] != RES_OK {
                return OperationOutput::abort(res_error(&response));
            }
            OperationOutput::ok([format!("Deleted release {target}")])
        }
        "fetch" | "verify" => {
            let Some(target) = target else {
                return OperationOutput::abort("No target specified");
            };
            let signer_hash = match signer {
                Some(s) => {
                    if s.len() != 32 {
                        return OperationOutput::abort(
                            "Invalid required signer identity hash length",
                        );
                    }
                    match decode_hex(s).and_then(|b| <[u8; 16]>::try_from(b).ok()) {
                        Some(hash) => Some(hash),
                        None => {
                            return OperationOutput::abort("Invalid required signer identity hash")
                        }
                    }
                }
                None => None,
            };
            release_fetch(
                client,
                &repo_path,
                target,
                signer_hash.as_ref(),
                offline || operation == "verify",
            )
            .await
        }
        "create" => {
            let Some(target) = target else {
                return OperationOutput::abort("No target specified");
            };
            let signer_identity = match signer {
                Some(path) => {
                    let path = expand_user(path);
                    match load_private_identity(&path) {
                        Ok(identity) => Some(identity),
                        Err(_) => {
                            return OperationOutput::abort(format!(
                                "Could not load signer identity from {}",
                                path.display()
                            ))
                        }
                    }
                }
                None => None,
            };
            if no_upload {
                // -L/--local: generate the manifest locally, no upload.
                return release_create_local(
                    client,
                    &repo_path,
                    remote,
                    target,
                    signer_identity.as_ref(),
                    name,
                )
                .await;
            }
            release_create(
                client,
                &repo_path,
                remote,
                target,
                signer_identity.as_ref(),
                name,
            )
            .await
        }
        _ => OperationOutput::abort("Invalid release operation"),
    }
}

async fn release_fetch(
    client: &RemoteClient,
    repo_path: &str,
    target: &str,
    signer: Option<&[u8; 16]>,
    offline: bool,
) -> OperationOutput {
    let _ = offline;
    let Some((tag, artifact)) = target.split_once(':') else {
        return OperationOutput::abort("Invalid release specification");
    };
    let manifest_path = match fetch_release_artifact(client, repo_path, tag, "manifest.rsm").await {
        Ok(p) => p,
        Err(err) => return OperationOutput::abort(err),
    };
    let Ok(rsg) = std::fs::read(&manifest_path) else {
        return OperationOutput::abort("Could not read release manifest");
    };
    let Some(view) = unpack_rsg(&rsg) else {
        return OperationOutput::abort("No embedded message in release manifest");
    };
    let Some(message) = view.message.clone() else {
        return OperationOutput::abort("No embedded message in release manifest");
    };
    let Some((view, signing_identity)) = validate_rsg(&rsg, &message, signer) else {
        return OperationOutput::abort(match signer {
            Some(hash) => format!(
                "Release manifest not signed by {pretty}",
                pretty = prettyhexrep(hash)
            ),
            None => "Could not validate release manifest signature".to_string(),
        });
    };
    let mut out = vec![format!(
        "Release manifest validated, signed by {signing_identity}"
    )];
    let meta = &view.meta;
    if let Err(reason) = check_release_rsm_structure(meta) {
        return OperationOutput::abort(reason);
    }
    let name = map_get(meta, "name")
        .and_then(value_str)
        .unwrap_or_default();
    let version = map_get(meta, "version")
        .and_then(value_str)
        .unwrap_or_default();
    let manifest_out = PathBuf::from(format!("{name}_{version}.{MSG_EXT}"));
    if std::fs::write(&manifest_out, &rsg).is_err() {
        return OperationOutput::abort("Could not write manifest");
    }
    let artifacts = map_get(meta, "artifacts")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if artifacts.is_empty() {
        return OperationOutput::abort("Release manifest contains no artifacts");
    }
    let fetch_artifacts: Vec<rmpv::Value> = if artifact == "all" {
        artifacts
    } else {
        artifacts
            .into_iter()
            .filter(|entry| {
                let name = map_get(entry, "name")
                    .and_then(value_str)
                    .unwrap_or_default();
                fnmatch(&name, artifact)
            })
            .collect()
    };
    if fetch_artifacts.is_empty() {
        return OperationOutput::abort("No available artifacts specified for fetch");
    }
    out.push(format!(
        "Fetching {} artifact{}...",
        fetch_artifacts.len(),
        if fetch_artifacts.len() == 1 { "" } else { "s" }
    ));
    let mut valid_count = 0usize;
    for entry in &fetch_artifacts {
        let name = map_get(entry, "name")
            .and_then(value_str)
            .unwrap_or_default();
        let base = Path::new(&name)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let rsg_data = map_get(entry, "rsg")
            .and_then(value_bin)
            .map(|b| b.to_vec());
        let existing = Path::new(&base);
        if existing.exists() {
            if let Some(rsg_bytes) = &rsg_data {
                if let Ok(contents) = std::fs::read(existing) {
                    if validate_rsg(rsg_bytes, &contents, signer).is_some() {
                        out.push(format!(
                            "Existing file {base} validated, not fetching again"
                        ));
                        valid_count += 1;
                        continue;
                    }
                }
            }
            out.push(format!(
                "Existing file {base} does not match manifest, fetching and overwriting"
            ));
        }
        let artifact_path = match fetch_release_artifact(client, repo_path, tag, &base).await {
            Ok(path) => path,
            Err(err) => return OperationOutput::abort(err),
        };
        if let Some(rsg_bytes) = &rsg_data {
            if let Ok(contents) = std::fs::read(&artifact_path) {
                if validate_rsg(rsg_bytes, &contents, signer).is_none() {
                    return OperationOutput::abort(format!(
                        "Fetched file {base} does not match manifest, aborting"
                    ));
                }
                valid_count += 1;
            }
        }
        let _ = std::fs::copy(&artifact_path, Path::new(&base));
    }
    let _ = valid_count;
    OperationOutput::ok(out)
}

async fn fetch_release_artifact(
    client: &RemoteClient,
    repo_path: &str,
    tag: &str,
    artifact_name: &str,
) -> Result<PathBuf, String> {
    let request = rmpv::Value::Map(vec![
        (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
        (vstr("operation"), vstr("fetch")),
        (vstr("tag"), vstr(tag)),
        (vstr("artifact"), vstr(artifact_name)),
    ]);
    let response = client
        .send_request(PATH_RELEASE, request, Duration::from_secs(7200))
        .await?;
    let Some(metadata) = &response.metadata else {
        let status = response.data.first().copied().unwrap_or(RES_REMOTE_FAIL);
        let msg = String::from_utf8_lossy(&response.data[1..]).to_string();
        return Err(match status {
            RES_INVALID_REQ => "Remote error: Invalid request".to_string(),
            RES_NOT_FOUND | RES_DISALLOWED => msg,
            _ => format!("Remote error: {msg}"),
        });
    };
    if map_get(metadata, "name").is_none() {
        return Err("Invalid result metadata on fetch response".to_string());
    }
    let path = std::env::temp_dir().join(format!(
        "rngit-fetch-{}-{}",
        std::process::id(),
        hex_encode(&sha256(format!("{tag}/{artifact_name}").as_bytes())[..8])
    ));
    std::fs::write(&path, &response.data).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Minimal fnmatch for artifact selection (`*` and `?` wildcards).
fn fnmatch(name: &str, pattern: &str) -> bool {
    fn inner(name: &[u8], pattern: &[u8]) -> bool {
        match pattern.split_first() {
            None => name.is_empty(),
            Some((b'*', rest)) => {
                for skip in 0..=name.len() {
                    if inner(&name[skip..], rest) {
                        return true;
                    }
                }
                false
            }
            Some((b'?', rest)) => !name.is_empty() && inner(&name[1..], rest),
            Some((&c, rest)) => !name.is_empty() && name[0] == c && inner(&name[1..], rest),
        }
    }
    inner(name.as_bytes(), pattern.as_bytes())
}

async fn release_create(
    client: &RemoteClient,
    repo_path: &str,
    remote: &str,
    target: &str,
    signer: Option<&PrivateIdentity>,
    name: Option<&str>,
) -> OperationOutput {
    let Some((tag, artifacts_dir)) = target.split_once(':') else {
        return OperationOutput::abort(
            "Invalid release specification\nDid you provide both a tag and artifacts path such as \"1.0.0:./dist\"?",
        );
    };
    let artifacts_path = expand_user(artifacts_dir);
    if !artifacts_path.is_dir() {
        return OperationOutput::abort("Specified artifacts directory does not exist");
    }
    let commit_hash = tokio::process::Command::new("git")
        .args(["rev-list", "-n", "1", tag])
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let commit_hash = match commit_hash {
        Some(hash) if !hash.is_empty() => hash,
        _ => {
            return OperationOutput::abort(format!(
            "Could not get commit hash for tag {tag}. Does the tag exist in the local repository?"
        ))
        }
    };
    let mut artifacts: Vec<String> = std::fs::read_dir(&artifacts_path)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    artifacts
        .retain(|a| !a.ends_with(&format!(".{SIG_EXT}")) && !a.ends_with(&format!(".{MSG_EXT}")));
    if artifacts.is_empty() {
        return OperationOutput::abort("No files found in specified artifact directory");
    }
    let signer = signer.cloned().unwrap_or_else(|| client.identity.clone());
    let mut out = vec![format!("Creating release {tag}")];
    let Some(notes) = edit_release_notes(tag) else {
        return OperationOutput::ok(["Release creation cancelled".to_string()]);
    };
    let release_time = now_f64() as i64;
    let release_time_iso = fmt_time(release_time as f64, "%Y-%m-%dT%H:%M:%SZ");
    let package_name = name.map(str::to_string).unwrap_or_else(|| {
        repo_path
            .split('/')
            .next_back()
            .unwrap_or_default()
            .to_string()
    });
    let origin = remote
        .trim_start_matches(PROTO_SPEC)
        .split('/')
        .next()
        .and_then(decode_hex)
        .unwrap_or_default();

    // Sign artifacts and build the manifest.
    let mut manifest_artifacts: Vec<rmpv::Value> = Vec::new();
    for artifact in &artifacts {
        let artifact_path = artifacts_path.join(artifact);
        let Ok(data) = std::fs::read(&artifact_path) else {
            return OperationOutput::abort("Release manifest generation failed");
        };
        let artifact_meta = vec![(vstr("timestamp"), rmpv::Value::from(release_time as u64))];
        let rsg = pack_rsg(&signer, &data, false, &artifact_meta);
        let signature_path = artifact_path.with_extension("rsg");
        let mut sig_path = artifact_path.clone().into_os_string();
        sig_path.push(format!(".{SIG_EXT}"));
        let _ = signature_path;
        if std::fs::write(PathBuf::from(sig_path), &rsg).is_err() {
            return OperationOutput::abort("Release manifest generation failed");
        }
        manifest_artifacts.push(rmpv::Value::Map(vec![
            (vstr("name"), vstr(artifact)),
            (vstr("rsg"), vbin(&rsg)),
        ]));
    }
    let manifest_meta = vec![
        (vstr("name"), vstr(&package_name)),
        (vstr("version"), vstr(tag)),
        (vstr("released"), vstr(&release_time_iso)),
        (vstr("timestamp"), rmpv::Value::from(release_time as u64)),
        (vstr("origin"), vbin(&origin)),
        (vstr("path"), vstr(repo_path)),
        (vstr("commit"), vstr(&commit_hash)),
        (vstr("artifacts"), rmpv::Value::Array(manifest_artifacts)),
    ];
    let manifest = pack_rsg(&signer, notes.as_bytes(), true, &manifest_meta);
    let manifest_name = format!("manifest.{MSG_EXT}");
    let manifest_path = artifacts_path.join(&manifest_name);
    if std::fs::write(&manifest_path, &manifest).is_err() {
        return OperationOutput::abort("Release manifest generation failed");
    }
    let mut upload_list: Vec<String> = artifacts.clone();
    for artifact in &artifacts {
        upload_list.push(format!("{artifact}.{SIG_EXT}"));
    }
    upload_list.push(manifest_name.clone());

    // Step 1: init.
    let init = rmpv::Value::Map(vec![
        (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
        (vstr("operation"), vstr("create")),
        (vstr("step"), vstr("init")),
        (vstr("tag"), vstr(tag)),
        (vstr("hash"), vstr(&commit_hash)),
        (vstr("notes"), vstr(&notes)),
        (vstr("notes_format"), vstr("markdown")),
    ]);
    match client
        .send_request(PATH_RELEASE, init, Duration::from_secs(120))
        .await
    {
        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {}
        Ok(response) => {
            return OperationOutput::abort(format!(
                "Server error during init: {}",
                String::from_utf8_lossy(&response.data[1..])
            ))
        }
        Err(err) => return OperationOutput::abort(err),
    }
    out.push("Release initialized".to_string());
    out.push(format!(
        "\nSending {} artifact{}...",
        upload_list.len(),
        if upload_list.len() == 1 { "" } else { "s" }
    ));

    // Step 2: upload each artifact (including .rsg signatures and manifest).
    for artifact in &upload_list {
        let artifact_path = artifacts_path.join(artifact);
        let Ok(data) = std::fs::read(&artifact_path) else {
            return OperationOutput::abort(format!("Could not read {artifact}"));
        };
        let request = rmpv::Value::Map(vec![
            (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
            (vstr("operation"), vstr("create")),
            (vstr("step"), vstr("artifact")),
            (vstr("tag"), vstr(tag)),
            (vstr("artifact_name"), vstr(artifact)),
            (vstr("artifact_data"), vbin(&data)),
        ]);
        match client
            .send_request(PATH_RELEASE, request, Duration::from_secs(7200))
            .await
        {
            Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
                out.push(format!("  {artifact} ({} B) transferred", data.len()));
            }
            Ok(response) => {
                out.push(format!(
                    "  Failed to send {artifact}: {}",
                    String::from_utf8_lossy(&response.data[1..])
                ));
            }
            Err(err) => return OperationOutput::abort(err),
        }
    }

    // Step 3: finalize.
    let finalize = rmpv::Value::Map(vec![
        (rmpv::Value::from(IDX_REPOSITORY), vstr(repo_path)),
        (vstr("operation"), vstr("create")),
        (vstr("step"), vstr("finalize")),
        (vstr("tag"), vstr(tag)),
    ]);
    match client
        .send_request(PATH_RELEASE, finalize, Duration::from_secs(300))
        .await
    {
        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
            out.push(format!("Release {tag} published"));
            OperationOutput::ok(out)
        }
        Ok(response) => OperationOutput::abort(format!(
            "Server error during finalize: {}",
            String::from_utf8_lossy(&response.data[1..])
        )),
        Err(err) => OperationOutput::abort(err),
    }
}

/// `-L/--local` variant: sign artifacts + write manifest locally without
/// uploading anything to the node.
async fn release_create_local(
    client: &RemoteClient,
    repo_path: &str,
    remote: &str,
    target: &str,
    signer: Option<&PrivateIdentity>,
    name: Option<&str>,
) -> OperationOutput {
    let Some((tag, artifacts_dir)) = target.split_once(':') else {
        return OperationOutput::abort("Invalid release specification");
    };
    let artifacts_path = expand_user(artifacts_dir);
    if !artifacts_path.is_dir() {
        return OperationOutput::abort("Specified artifacts directory does not exist");
    }
    let commit_hash = tokio::process::Command::new("git")
        .args(["rev-list", "-n", "1", tag])
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let mut artifacts: Vec<String> = std::fs::read_dir(&artifacts_path)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    artifacts
        .retain(|a| !a.ends_with(&format!(".{SIG_EXT}")) && !a.ends_with(&format!(".{MSG_EXT}")));
    if artifacts.is_empty() {
        return OperationOutput::abort("No files found in specified artifact directory");
    }
    let signer = signer.cloned().unwrap_or_else(|| client.identity.clone());
    let Some(notes) = edit_release_notes(tag) else {
        return OperationOutput::ok(["Release creation cancelled".to_string()]);
    };
    let release_time = now_f64() as i64;
    let package_name = name.map(str::to_string).unwrap_or_else(|| {
        repo_path
            .split('/')
            .next_back()
            .unwrap_or_default()
            .to_string()
    });
    let origin = remote
        .trim_start_matches(PROTO_SPEC)
        .split('/')
        .next()
        .and_then(decode_hex)
        .unwrap_or_default();
    let mut manifest_artifacts: Vec<rmpv::Value> = Vec::new();
    for artifact in &artifacts {
        let artifact_path = artifacts_path.join(artifact);
        let Ok(data) = std::fs::read(&artifact_path) else {
            return OperationOutput::abort("Release manifest generation failed");
        };
        let artifact_meta = vec![(vstr("timestamp"), rmpv::Value::from(release_time as u64))];
        let rsg = pack_rsg(&signer, &data, false, &artifact_meta);
        let mut sig_path = artifact_path.clone().into_os_string();
        sig_path.push(format!(".{SIG_EXT}"));
        if std::fs::write(PathBuf::from(sig_path), &rsg).is_err() {
            return OperationOutput::abort("Release manifest generation failed");
        }
        manifest_artifacts.push(rmpv::Value::Map(vec![
            (vstr("name"), vstr(artifact)),
            (vstr("rsg"), vbin(&rsg)),
        ]));
    }
    let manifest_meta = vec![
        (vstr("name"), vstr(&package_name)),
        (vstr("version"), vstr(tag)),
        (
            vstr("released"),
            vstr(&fmt_time(release_time as f64, "%Y-%m-%dT%H:%M:%SZ")),
        ),
        (vstr("timestamp"), rmpv::Value::from(release_time as u64)),
        (vstr("origin"), vbin(&origin)),
        (vstr("path"), vstr(repo_path)),
        (vstr("commit"), vstr(&commit_hash)),
        (vstr("artifacts"), rmpv::Value::Array(manifest_artifacts)),
    ];
    let manifest = pack_rsg(&signer, notes.as_bytes(), true, &manifest_meta);
    let manifest_path = artifacts_path.join(format!("manifest.{MSG_EXT}"));
    if std::fs::write(&manifest_path, &manifest).is_err() {
        return OperationOutput::abort("Release manifest generation failed");
    }
    OperationOutput::ok([format!(
        "Local release {package_name}:{tag} generated successfully in {target}"
    )])
}

/// `rngit perms <rns://hash/group>` or `<rns://hash/group/repo>`
async fn op_perms(client: &RemoteClient, remote: &str, config_dir: &Path) -> OperationOutput {
    let aliases = load_client_config(config_dir).destination_aliases;
    let (_, group, repo) = match parse_remote_url(remote, &aliases, false) {
        Ok(parts) => parts,
        Err(err) => return OperationOutput::abort(err),
    };
    let is_group = repo.is_none();
    let (target, idx_key, label) = if is_group {
        (
            group.clone().unwrap_or_default(),
            IDX_GROUP,
            format!("group {}", group.unwrap_or_default()),
        )
    } else {
        let path = format!(
            "{}/{}",
            group.unwrap_or_default(),
            repo.clone().unwrap_or_default()
        );
        (path.clone(), IDX_REPOSITORY, path)
    };
    let send = |pairs: Vec<(rmpv::Value, rmpv::Value)>| {
        let request = rmpv::Value::Map(pairs);
        async move {
            client
                .send_request(PATH_PERMS, request, Duration::from_secs(120))
                .await
        }
    };
    let get_request = vec![
        (rmpv::Value::from(idx_key), vstr(&target)),
        (
            vstr("operation"),
            vstr(if is_group { "gperms" } else { "rperms" }),
        ),
        (vstr("step"), vstr("get")),
    ];
    let current = match send(get_request).await {
        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
            if response.data.len() > 1 {
                unpack_value(&response.data[1..])
                    .and_then(|v| map_get(&v, "content").and_then(value_str))
                    .unwrap_or_default()
            } else {
                String::new()
            }
        }
        Ok(response) => {
            if !response.data.is_empty() && response.data[0] == RES_NOT_FOUND {
                String::new()
            } else {
                return OperationOutput::abort(res_error(&response));
            }
        }
        Err(err) => return OperationOutput::abort(err),
    };
    let Some(edited) = edit_permissions(&current) else {
        return OperationOutput::ok(["Edit cancelled".to_string()]);
    };
    let set_request = vec![
        (rmpv::Value::from(idx_key), vstr(&target)),
        (
            vstr("operation"),
            vstr(if is_group { "gperms" } else { "rperms" }),
        ),
        (vstr("step"), vstr("set")),
        (vstr("content"), vstr(&edited)),
    ];
    match send(set_request).await {
        Ok(response) if !response.data.is_empty() && response.data[0] == RES_OK => {
            OperationOutput::ok([format!("Permissions updated for {label}")])
        }
        Ok(response) => OperationOutput::abort(res_error(&response)),
        Err(err) => OperationOutput::abort(err),
    }
}

/// `rngit work <remote> <operation> ...`
async fn op_work(
    client: &RemoteClient,
    remote: &str,
    config_dir: &Path,
    operation: &str,
    doc_id: Option<i64>,
    scope: &str,
    title: Option<&str>,
) -> OperationOutput {
    let repo_path = match repo_path_of(remote, config_dir) {
        Ok(p) => p,
        Err(err) => return OperationOutput::abort(err),
    };
    let request_for = |extra: Vec<(rmpv::Value, rmpv::Value)>| {
        let mut pairs = vec![(rmpv::Value::from(IDX_REPOSITORY), vstr(&repo_path))];
        pairs.extend(extra);
        rmpv::Value::Map(pairs)
    };
    let send = |request: rmpv::Value, timeout: Duration| async move {
        client.send_request(PATH_WORK, request, timeout).await
    };
    let require_ok =
        |response: Result<RemoteResponse, String>| -> Result<RemoteResponse, OperationOutput> {
            match response {
                Ok(r) if !r.data.is_empty() && r.data[0] == RES_OK => Ok(r),
                Ok(r) => Err(OperationOutput::abort(res_error(&r))),
                Err(err) => Err(OperationOutput::abort(err)),
            }
        };
    match operation {
        "list" => {
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("list")),
                        (vstr("scope"), vstr(scope)),
                    ]),
                    Duration::from_secs(120),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let result = if response.data.len() > 1 {
                unpack_value(&response.data[1..])
            } else {
                None
            };
            let scopes_to_show: Vec<&str> = if scope == "all" {
                vec!["active", "completed", "proposed"]
            } else {
                vec![scope]
            };
            let mut out = Vec::new();
            let mut shown_any = false;
            for scope_name in &scopes_to_show {
                let docs = result
                    .as_ref()
                    .and_then(|r| map_get(r, scope_name))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if !docs.is_empty() {
                    shown_any = true;
                    let header = format!("\n{} documents", capitalize(scope_name));
                    out.push(header.clone());
                    out.push("=".repeat(header.len()));
                    out.push(String::new());
                    out.push(format!(
                        "{:<4} {:<30} {:<17} {:<18} Comments",
                        "ID", "Title", "Author", "Created"
                    ));
                    out.push("-".repeat(80));
                    for doc in &docs {
                        let id = map_get(doc, "id").and_then(value_i64).unwrap_or(0);
                        let mut doc_title = map_get(doc, "title")
                            .and_then(value_str)
                            .unwrap_or_else(|| "Untitled".into());
                        if doc_title.len() > 29 {
                            doc_title = format!("{}\u{2026}", &doc_title[..29]);
                        }
                        let author = map_get(doc, "author")
                            .and_then(value_str)
                            .unwrap_or_default();
                        let author = format!("{}\u{2026}", &author[..author.len().min(16)]);
                        let created = map_get(doc, "created").and_then(value_f64).unwrap_or(0.0);
                        let created_str = if created > 0.0 {
                            fmt_time(created, "%Y-%m-%d %H:%M")
                        } else {
                            "unknown".to_string()
                        };
                        let comments = map_get(doc, "comments").and_then(value_i64).unwrap_or(0);
                        out.push(format!(
                            "{id:<4} {doc_title:<30} {author:<17} {created_str:<18} {comments}"
                        ));
                    }
                    out.push(String::new());
                } else if scope != "all" {
                    out.push(format!("No {scope_name} work documents found."));
                }
            }
            if scope == "all" && !shown_any {
                out.push("No work documents found.".to_string());
            }
            OperationOutput::ok(out)
        }
        "view" => {
            let Some(doc_id) = doc_id else {
                return OperationOutput::abort("No document ID specified");
            };
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("view")),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                        (vstr("scope"), vstr(scope)),
                    ]),
                    Duration::from_secs(120),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let Some(doc) = (response.data.len() > 1)
                .then(|| unpack_value(&response.data[1..]))
                .flatten()
            else {
                return OperationOutput::abort("Empty response from remote");
            };
            let meta = map_get(&doc, "meta").cloned().unwrap_or(rmpv::Value::Nil);
            let mut author_str = format!("{} (not locally validated)", meta_author_display(&meta));
            let mut signature_str = "Document not signed".to_string();
            let signature = map_get(&meta, "signature")
                .and_then(value_bin)
                .map(|b| b.to_vec());
            let pubkey = map_get(&meta, "identity")
                .and_then(value_bin)
                .map(|b| b.to_vec());
            let content = map_get(&doc, "content")
                .and_then(value_str)
                .unwrap_or_default();
            if let (Some(signature), Some(pubkey)) = (signature, pubkey) {
                if signature.len() == SIG_BYTES && pubkey.len() == KEY_BYTES {
                    signature_str = "Not valid".to_string();
                    let identity = Identity::new_from_slices(&pubkey[..32], &pubkey[32..]);
                    let sig = Signature::from_bytes(
                        &<[u8; SIG_BYTES]>::try_from(&signature[..]).unwrap(),
                    );
                    if identity.verify(content.as_bytes(), &sig).is_ok() {
                        signature_str = "Valid".to_string();
                        author_str = prettyhexrep(identity.address_hash.as_slice());
                    }
                }
            }
            let doc_scope = map_get(&doc, "scope")
                .and_then(value_str)
                .unwrap_or_else(|| scope.to_string());
            let title_str = map_get(&meta, "title")
                .and_then(value_str)
                .unwrap_or_default();
            let dt = format!("{title_str} (#{doc_id})");
            let mut out = vec![dt.clone(), "=".repeat(dt.len())];
            out.push(format!("Author    : {author_str}"));
            out.push(format!("Signature : {signature_str}"));
            out.push(format!("Status    : {}", capitalize(&doc_scope)));
            out.push(format!(
                "Created   : {}",
                fmt_time(
                    map_get(&meta, "created").and_then(value_f64).unwrap_or(0.0),
                    "%Y-%m-%d %H:%M:%S"
                )
            ));
            out.push(format!(
                "Edited    : {}",
                fmt_time(
                    map_get(&meta, "edited").and_then(value_f64).unwrap_or(0.0),
                    "%Y-%m-%d %H:%M:%S"
                )
            ));
            out.push(format!(
                "Format    : {}",
                map_get(&meta, "format")
                    .and_then(value_str)
                    .unwrap_or_else(|| "markdown".into())
            ));
            let comments = map_get(&doc, "comments")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            out.push(format!("Updates   : {}", comments.len()));
            out.push(String::new());
            out.push(content);
            if !comments.is_empty() {
                out.push("\nUpdates".to_string());
                out.push("=======".to_string());
                for c in &comments {
                    let c_id = map_get(c, "id").and_then(value_i64).unwrap_or(0);
                    let c_author = map_get(c, "author").and_then(value_str).unwrap_or_default();
                    let c_created = map_get(c, "created").and_then(value_f64).unwrap_or(0.0);
                    let ts = format!(
                        "#{c_id} by {c_author} at {}",
                        fmt_time(c_created, "%Y-%m-%d %H:%M:%S")
                    );
                    out.push(format!("\n{ts}"));
                    out.push("-".repeat(ts.len()));
                    out.push(
                        map_get(c, "content")
                            .and_then(value_str)
                            .unwrap_or_default(),
                    );
                }
            }
            out.push(String::new());
            OperationOutput::ok(out)
        }
        "create" | "propose" => {
            let Some(title) = title else {
                return OperationOutput::abort("No title specified");
            };
            let Some(content) = edit_work_content(title, "", false) else {
                return OperationOutput::ok(["Creation cancelled".to_string()]);
            };
            let signature = client.identity.sign(content.as_bytes());
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr(operation)),
                        (vstr("title"), vstr(title)),
                        (vstr("content"), vstr(&content)),
                        (vstr("format"), vstr("markdown")),
                        (vstr("signature"), vbin(&signature.to_bytes())),
                    ]),
                    Duration::from_secs(600),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let result = (response.data.len() > 1)
                .then(|| unpack_value(&response.data[1..]))
                .flatten();
            match result {
                Some(result) => {
                    let scope = map_get(&result, "scope")
                        .and_then(value_str)
                        .unwrap_or_default();
                    let id = map_get(&result, "id").and_then(value_i64).unwrap_or(0);
                    OperationOutput::ok([format!("Work document created as {scope} #{id}")])
                }
                None => OperationOutput::ok(["Work document created".to_string()]),
            }
        }
        "edit" => {
            let Some(doc_id) = doc_id else {
                return OperationOutput::abort("No document ID specified");
            };
            // Fetch current doc for editor seed + title default.
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("view")),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                        (vstr("scope"), vstr(scope)),
                    ]),
                    Duration::from_secs(600),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let doc = (response.data.len() > 1)
                .then(|| unpack_value(&response.data[1..]))
                .flatten()
                .unwrap_or(rmpv::Value::Nil);
            let current_content = map_get(&doc, "content")
                .and_then(value_str)
                .unwrap_or_default();
            let current_title = map_get(&doc, "meta")
                .and_then(|m| map_get(m, "title"))
                .and_then(value_str)
                .unwrap_or_default();
            let Some(content) = edit_work_content(&current_title, &current_content, false) else {
                return OperationOutput::ok(["Edit cancelled".to_string()]);
            };
            let signature = client.identity.sign(content.as_bytes());
            let title = title.map(str::to_string).unwrap_or(current_title);
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("edit")),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                        (vstr("scope"), vstr(scope)),
                        (vstr("content"), vstr(&content)),
                        (vstr("title"), vstr(&title)),
                        (vstr("signature"), vbin(&signature.to_bytes())),
                    ]),
                    Duration::from_secs(600),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let _ = response;
            OperationOutput::ok([format!("Work document {scope} #{doc_id} updated")])
        }
        "comment" => {
            let Some(doc_id) = doc_id else {
                return OperationOutput::abort("No document ID specified");
            };
            let Some(content) =
                edit_work_content(&format!("Update on document #{doc_id}"), "", true)
            else {
                return OperationOutput::ok(["Update cancelled".to_string()]);
            };
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("comment")),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                        (vstr("scope"), vstr(scope)),
                        (vstr("content"), vstr(&content)),
                        (vstr("format"), vstr("markdown")),
                    ]),
                    Duration::from_secs(600),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let id = (response.data.len() > 1)
                .then(|| unpack_value(&response.data[1..]))
                .flatten()
                .and_then(|v| map_get(&v, "id").and_then(value_i64))
                .unwrap_or(0);
            OperationOutput::ok([format!("Update #{id} added to {scope} document #{doc_id}")])
        }
        "delete" => {
            let Some(doc_id) = doc_id else {
                return OperationOutput::abort("No document ID specified");
            };
            print!("Are you sure you want to delete {scope} work document #{doc_id}? [y/N]: ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let mut confirm = String::new();
            let _ = std::io::stdin().read_line(&mut confirm);
            if confirm.trim().to_lowercase() != "y" {
                return OperationOutput::ok(["Deletion cancelled".to_string()]);
            }
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("delete")),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                        (vstr("scope"), vstr(scope)),
                    ]),
                    Duration::from_secs(120),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let _ = response;
            OperationOutput::ok([format!("Work document {scope} #{doc_id} deleted")])
        }
        "complete" | "activate" => {
            let Some(doc_id) = doc_id else {
                return OperationOutput::abort("No document ID specified");
            };
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr(operation)),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                    ]),
                    Duration::from_secs(120),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let result = (response.data.len() > 1)
                .then(|| unpack_value(&response.data[1..]))
                .flatten();
            let scope_str = result
                .as_ref()
                .and_then(|v| map_get(v, "scope"))
                .and_then(value_str)
                .unwrap_or_else(|| scope.to_string());
            let verb = if operation == "complete" {
                "Completed"
            } else {
                "Activated"
            };
            OperationOutput::ok([format!("{verb} work document {scope_str} #{doc_id}")])
        }
        "perms" => {
            let Some(doc_id) = doc_id else {
                return OperationOutput::abort("No document ID specified");
            };
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("perms")),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                        (vstr("step"), vstr("get")),
                    ]),
                    Duration::from_secs(120),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let current = (response.data.len() > 1)
                .then(|| unpack_value(&response.data[1..]))
                .flatten()
                .and_then(|v| map_get(&v, "content").and_then(value_str))
                .unwrap_or_default();
            let Some(edited) = edit_permissions(&current) else {
                return OperationOutput::ok(["Edit cancelled".to_string()]);
            };
            let response = match require_ok(
                send(
                    request_for(vec![
                        (vstr("operation"), vstr("perms")),
                        (vstr("doc_id"), rmpv::Value::from(doc_id as u64)),
                        (vstr("step"), vstr("set")),
                        (vstr("content"), vstr(&edited)),
                    ]),
                    Duration::from_secs(120),
                )
                .await,
            ) {
                Ok(r) => r,
                Err(out) => return out,
            };
            let _ = response;
            OperationOutput::ok([format!("Permissions updated for document #{doc_id}")])
        }
        _ => OperationOutput::abort("Invalid work operation"),
    }
}

fn meta_author_display(meta: &rmpv::Value) -> String {
    match map_get(meta, "author") {
        Some(rmpv::Value::Binary(b)) => hex_encode(b),
        Some(rmpv::Value::String(s)) => s.as_str().unwrap_or("").to_string(),
        _ => "?".to_string(),
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// git-remote-rns: git remote-helper protocol over stdin/stdout
// ---------------------------------------------------------------------------

/// Quote a push error message for the remote-helper protocol.
fn escape_for_stdout(value: &str) -> String {
    let mut escaped = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push_str("\\t"),
            '\r' => escaped.push_str("\\r"),
            c if (c as u32) < 32 || (c as u32) > 126 => {
                for b in c.to_string().as_bytes() {
                    escaped.push_str(&format!("\\x{b:02x}"));
                }
            }
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

/// A write failure means git closed the helper channel — drop the output
/// instead of panicking on the default `println!` EPIPE path.
fn git_stdout(line: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn git_stderr(line: &str) {
    use std::io::Write;
    let mut out = std::io::stderr().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

async fn read_git_line(
    rx: &Arc<std::sync::Mutex<std::sync::mpsc::Receiver<Option<String>>>>,
) -> Option<String> {
    let rx = rx.clone();
    tokio::task::spawn_blocking(move || rx.lock().ok().and_then(|rx| rx.recv().ok()).flatten())
        .await
        .ok()
        .flatten()
}

/// `git-remote-rns <name> <url>` entry point.
pub async fn remote_helper_main(args: &[String]) -> i32 {
    let url = match args.get(2) {
        Some(url) => url.clone(),
        None => {
            git_stderr("Missing remote URL");
            return 1;
        }
    };
    if !url.starts_with("rns://") {
        git_stderr(&format!("Invalid remote URL: {url}"));
        return 1;
    }
    let parts: Vec<&str> = url[6..].splitn(3, '/').collect();
    if parts.len() != 3 {
        git_stderr(&format!("Invalid remote URL: {url}"));
        return 1;
    }
    let repo_path = format!("{}/{}", parts[1], parts[2]);

    let rngit_dir = std::env::var("RNGIT_CONFIG")
        .ok()
        .map(|p| expand_user(&p))
        .unwrap_or_else(|| resolve_rngit_config_dir(None));
    let rns_dir = std::env::var("RNS_CONFIG")
        .ok()
        .map(|p| expand_user(&p))
        .unwrap_or_else(|| resolve_config_dir(None));
    let options = ClientOptions {
        rngit_config_dir: rngit_dir,
        rns_config_dir: rns_dir,
        ..Default::default()
    };
    let mut client = match RemoteClient::connect(&options, &url).await {
        Ok(client) => client,
        Err(err) => {
            git_stderr(&format!("Link establishment failed: {err}"));
            return 1;
        }
    };

    // Read git's remote-helper commands from stdin on a blocking thread.
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        loop {
            let mut line = String::new();
            match handle.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    break;
                }
                Ok(_) => {
                    let _ = tx.send(Some(line.trim_end().to_string()));
                }
            }
        }
    });
    let rx = Arc::new(std::sync::Mutex::new(rx));

    let work_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut fetch_queue: Vec<(String, String)> = Vec::new();
    let mut push_queue: Vec<(String, String, bool)> = Vec::new();

    while let Some(line) = read_git_line(&rx).await {
        let line = line.trim().to_string();
        if line == "capabilities" {
            git_stdout("list");
            git_stdout("fetch");
            git_stdout("push");
            git_stdout("option");
            git_stdout("");
        } else if line.starts_with("list") {
            let for_push = line.trim() == "list for-push";
            match client.list_refs(&repo_path, for_push).await {
                Ok(refs) => {
                    if !refs.is_empty() {
                        git_stdout(refs.trim_end());
                    }
                    git_stdout("");
                }
                Err(err) => {
                    git_stderr(&err);
                    git_stdout("");
                }
            }
        } else if let Some(rest) = line.strip_prefix("option ") {
            let mut parts = rest.splitn(2, ' ');
            let opt_name = parts.next().unwrap_or("");
            let opt_value = parts.next().unwrap_or("");
            if opt_name == "progress" {
                let enabled = ["true", "1", "yes"].contains(&opt_value.to_lowercase().as_str());
                client.progress_enabled = enabled;
                git_stdout("ok");
            } else {
                git_stdout("unsupported");
            }
        } else if let Some(rest) = line.strip_prefix("fetch ") {
            let mut parts = rest.split_whitespace();
            let sha = parts.next().unwrap_or("").to_string();
            let name = parts.next().unwrap_or("").to_string();
            if !fetch_queue.contains(&(sha.clone(), name.clone())) {
                fetch_queue.push((sha, name));
            }
            push_queue.clear();
        } else if let Some(rest) = line.strip_prefix("push ") {
            let mut parts = rest.splitn(2, ':');
            let mut local = parts.next().unwrap_or("").to_string();
            let remote = parts.next().unwrap_or("").to_string();
            let mut force = false;
            if local.starts_with('+') {
                local = local[1..].to_string();
                force = true;
            }
            push_queue.push((local, remote, force));
            fetch_queue.clear();
        } else if line.is_empty() {
            if !fetch_queue.is_empty() {
                if let Err(err) = client
                    .fetch_refs(
                        &fetch_queue,
                        &repo_path,
                        &work_dir,
                        Duration::from_secs(7200),
                    )
                    .await
                {
                    git_stderr(&err);
                }
            }
            if !push_queue.is_empty() {
                let results = client
                    .push_refs(
                        &push_queue,
                        &repo_path,
                        &work_dir,
                        Duration::from_secs(7200),
                    )
                    .await;
                for (remote_ref, result) in results {
                    match result {
                        Ok(()) => git_stdout(&format!("ok {remote_ref}")),
                        Err(err) => {
                            git_stdout(&format!("error {remote_ref} {}", escape_for_stdout(&err)))
                        }
                    }
                }
            }
            fetch_queue.clear();
            push_queue.clear();
            git_stdout("");
        } else {
            git_stderr(&format!(
                "git-remote-rns failed: Unknown Git command: {line}"
            ));
            client.close().await;
            return 255;
        }
    }

    client.close().await;
    0
}

// ---------------------------------------------------------------------------
// rngit entry point (argv0 "rngit", `rn git`)
// ---------------------------------------------------------------------------

fn rngit_usage() -> String {
    "usage: rngit [OPTIONS] <command> [args...]\n\
     \n\
     rngit - Reticulum Git repositories\n\
     \n\
     commands:\n\
     node      - Run this node (default when no command is given)\n\
     create    - Create a repository on a remote node\n\
     release   - Manage releases (list|view|fetch|verify|create|latest|delete)\n\
     perms     - Manage permissions for a group or repository\n\
     work      - Manage work documents (list|view|create|propose|edit|delete|update|complete|activate|perms)\n\
     fork      - Fork a repository to a remote node\n\
     sync      - Sync a forked repository with its upstream\n\
     mirror    - Mirror a repository to a remote node"
        .to_string()
}

/// Argument dispatch. `args[0]` is the program name (ignored).
pub async fn rngit_main(args: &[String]) -> i32 {
    const VALID_COMMANDS: [&str; 8] = [
        "node", "create", "release", "perms", "work", "fork", "sync", "mirror",
    ];
    let mut config_dir: Option<PathBuf> = None;
    let mut rns_config_dir: Option<PathBuf> = None;
    let mut identity_path: Option<PathBuf> = None;
    let mut signer: Option<String> = None;
    let mut print_identity = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 1;
    // Options may precede the command; `-i`/`--identity` and `-s`/`--signer`
    // take values here, `--interactive`/`--service` remain flags.
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--config" => {
                i += 1;
                config_dir = args.get(i).map(|s| expand_user(s));
            }
            "--rnsconfig" => {
                i += 1;
                rns_config_dir = args.get(i).map(|s| expand_user(s));
            }
            "-i" | "--identity" => {
                i += 1;
                identity_path = args.get(i).map(|s| expand_user(s));
            }
            "-s" | "--signer" => {
                i += 1;
                signer = args.get(i).cloned();
            }
            "-p" | "--print-identity" => print_identity = true,
            "--interactive" | "--service" | "-v" | "--verbose" | "-q" | "--quiet" => {}
            "-h" | "--help" => {
                println!("{}", rngit_usage());
                return 0;
            }
            _ => break,
        }
        i += 1;
    }

    let mut command = "node";
    if i < args.len() {
        let candidate = &args[i];
        if VALID_COMMANDS.contains(&candidate.as_str()) {
            command = candidate.as_str();
            i += 1;
        }
        // Unknown first arg → node.
    }

    // Command-specific argument parsing.
    let mut name: Option<String> = None;
    let mut no_upload = false;
    let mut offline = false;
    let mut scope = "active".to_string();
    let mut title: Option<String> = None;
    let mut doc_id: Option<i64> = None;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--config" => {
                i += 1;
                config_dir = args.get(i).map(|s| expand_user(s));
            }
            "--rnsconfig" => {
                i += 1;
                rns_config_dir = args.get(i).map(|s| expand_user(s));
            }
            "-i" | "--identity" if command != "node" => {
                i += 1;
                identity_path = args.get(i).map(|s| expand_user(s));
            }
            "-i" | "--interactive" => {}
            "-p" | "--print-identity" => print_identity = true,
            "-s" | "--signer" if command != "node" => {
                i += 1;
                signer = args.get(i).cloned();
            }
            "-s" | "--service" | "-v" | "--verbose" | "-q" | "--quiet" => {}
            "-n" | "--name" => {
                i += 1;
                name = args.get(i).cloned();
            }
            "-L" | "--local" => no_upload = true,
            "-o" | "--offline" => offline = true,
            "--scope" => {
                i += 1;
                scope = args.get(i).cloned().unwrap_or_else(|| "active".to_string());
            }
            "-t" | "--title" => {
                i += 1;
                title = args.get(i).cloned();
            }
            "-d" | "--id" => {
                i += 1;
                doc_id = args.get(i).and_then(|s| s.parse().ok());
            }
            "-e" | "--no-editor" => {}
            _ => positional.push(arg.clone()),
        }
        i += 1;
    }

    let config_dir = config_dir.unwrap_or_else(|| resolve_rngit_config_dir(None));
    let rns_config_dir = rns_config_dir.unwrap_or_else(|| resolve_config_dir(None));

    match command {
        "node" => {
            if print_identity {
                return if print_node_identities(&config_dir).await {
                    0
                } else {
                    eprintln!("Could not load node identity");
                    1
                };
            }
            let options = NodeOptions {
                config_dir,
                rns_config_dir,
                udp_loopback: None,
                shutdown: None,
            };
            match serve(&options).await {
                Ok(_) => {
                    // serve() only returns once the jobs task ends; park.
                    std::future::pending::<()>().await;
                    0
                }
                Err(err) => {
                    eprintln!("Could not initialise git node: {err}");
                    1
                }
            }
        }
        _ => {
            let options = ClientOptions {
                rngit_config_dir: config_dir.clone(),
                rns_config_dir,
                identity_path,
                ..Default::default()
            };
            let remote = positional.first().cloned().unwrap_or_default();
            let needs_remote = match command {
                "create" | "release" | "perms" | "work" | "sync" => true,
                _ => positional.len() >= 2,
            };
            let connect_remote = if command == "fork" || command == "mirror" {
                positional.get(1).cloned().unwrap_or_default()
            } else {
                remote.clone()
            };
            if needs_remote && connect_remote.is_empty() {
                eprintln!("No remote specified");
                return 1;
            }
            let client = match RemoteClient::connect(&options, &connect_remote).await {
                Ok(client) => client,
                Err(err) => {
                    eprintln!("{err}");
                    return 1;
                }
            };
            let output = match command {
                "create" => op_create(&client, &remote, &config_dir).await,
                "sync" => op_sync(&client, &remote, &config_dir).await,
                "fork" => {
                    let source = positional.first().cloned().unwrap_or_default();
                    let target = positional.get(1).cloned().unwrap_or_default();
                    op_clone(&client, &target, &source, PATH_FORK, &config_dir).await
                }
                "mirror" => {
                    let source = positional.first().cloned().unwrap_or_default();
                    let target = positional.get(1).cloned().unwrap_or_default();
                    op_clone(&client, &target, &source, PATH_MIRROR, &config_dir).await
                }
                "perms" => op_perms(&client, &remote, &config_dir).await,
                "release" => {
                    let operation = positional.get(1).cloned().unwrap_or_default();
                    let target = positional.get(2).cloned();
                    op_release(
                        &client,
                        &remote,
                        &config_dir,
                        &operation,
                        target.as_deref(),
                        signer.as_deref(),
                        name.as_deref(),
                        no_upload,
                        offline,
                    )
                    .await
                }
                "work" => {
                    let operation = positional.get(1).cloned().unwrap_or_default();
                    // The CLI operation "update" maps to the "comment" request op.
                    let operation = if operation == "update" || operation == "comment" {
                        "comment".to_string()
                    } else {
                        operation
                    };
                    op_work(
                        &client,
                        &remote,
                        &config_dir,
                        &operation,
                        doc_id,
                        &scope,
                        title.as_deref(),
                    )
                    .await
                }
                _ => OperationOutput::abort("Unknown command"),
            };
            client.close().await;
            for line in &output.out {
                println!("{line}");
            }
            output.code
        }
    }
}

// ---------------------------------------------------------------------------
// git-sign-rns: SSHSIG-compatible commit signing for
// `git config gpg.ssh.program`. The signature blob is an RSG signature
// wrapped in the SSHSIG envelope.
// ---------------------------------------------------------------------------

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 1;
const SSHSIG_NAMESPACE: &[u8] = b"git";
const SSHSIG_HASH_ALGORITHM: &[u8] = b"sha256";

fn ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_ssh_string<'a>(buf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    if *cursor + 4 > buf.len() {
        return None;
    }
    let len = u32::from_be_bytes(buf[*cursor..*cursor + 4].try_into().ok()?) as usize;
    *cursor += 4;
    if *cursor + len > buf.len() {
        return None;
    }
    let out = &buf[*cursor..*cursor + len];
    *cursor += len;
    Some(out)
}

struct SshSig {
    #[allow(dead_code)]
    public_key: Vec<u8>,
    namespace: Vec<u8>,
    signature_data: Vec<u8>,
}

fn create_ssh_signature(identity: &PrivateIdentity, rsg: &[u8]) -> Vec<u8> {
    let mut pubkey_wire = Vec::new();
    ssh_string(&mut pubkey_wire, b"ssh-ed25519");
    ssh_string(
        &mut pubkey_wire,
        identity.as_identity().verifying_key_bytes(),
    );

    let mut blob = Vec::new();
    blob.extend_from_slice(SSHSIG_MAGIC);
    blob.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
    ssh_string(&mut blob, &pubkey_wire);
    ssh_string(&mut blob, SSHSIG_NAMESPACE);
    ssh_string(&mut blob, b"");
    ssh_string(&mut blob, SSHSIG_HASH_ALGORITHM);
    ssh_string(&mut blob, rsg);
    blob
}

fn parse_ssh_signature(sig_data: &[u8]) -> Option<SshSig> {
    if !sig_data.starts_with(SSHSIG_MAGIC) || sig_data.len() < 10 {
        return None;
    }
    if u32::from_be_bytes(sig_data[6..10].try_into().ok()?) != SSHSIG_VERSION {
        return None;
    }
    let mut cursor = 10;
    let public_key = read_ssh_string(sig_data, &mut cursor)?.to_vec();
    let namespace = read_ssh_string(sig_data, &mut cursor)?.to_vec();
    let _reserved = read_ssh_string(sig_data, &mut cursor)?;
    let _hash_algorithm = read_ssh_string(sig_data, &mut cursor)?;
    let signature_data = read_ssh_string(sig_data, &mut cursor)?.to_vec();
    Some(SshSig {
        public_key,
        namespace,
        signature_data,
    })
}

fn armor_ssh_signature(blob: &[u8]) -> String {
    let b64 = base64_encode(blob);
    let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END SSH SIGNATURE-----\n");
    out
}

fn unarmor_ssh_signature(armored: &str) -> Option<Vec<u8>> {
    let mut b64 = String::new();
    let mut in_sig = false;
    for line in armored.lines() {
        if line.contains("BEGIN SSH SIGNATURE") {
            in_sig = true;
            continue;
        }
        if line.contains("END SSH SIGNATURE") {
            break;
        }
        if in_sig {
            b64.push_str(line.trim());
        }
    }
    if b64.is_empty() {
        return None;
    }
    base64_decode(&b64)
}

/// The email-ish `author NAME <FIELD>` / `committer` / `tagger` principal
/// field inside a commit object.
fn extract_commit_field(message: &[u8], target: &[u8]) -> String {
    for line in message.split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            break;
        }
        if line.starts_with(target) {
            let spos = line.iter().position(|b| *b == b'<');
            let epos = line.iter().position(|b| *b == b'>');
            if let (Some(spos), Some(epos)) = (spos, epos) {
                if spos > target.len() && epos > spos && epos < line.len() - 1 {
                    return String::from_utf8_lossy(&line[spos + 1..epos]).to_string();
                }
            }
        }
    }
    String::new()
}

fn extract_commit_tagger(message: &[u8]) -> (String, bool) {
    let mut is_tag = false;
    for line in message.split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            break;
        }
        if line.starts_with(b"tag ") {
            is_tag = true;
        } else if line.starts_with(b"tagger ") && is_tag {
            let spos = line.iter().position(|b| *b == b'<');
            let epos = line.iter().position(|b| *b == b'>');
            if let (Some(spos), Some(epos)) = (spos, epos) {
                if spos > 7 && epos > spos && epos < line.len() - 1 {
                    return (
                        String::from_utf8_lossy(&line[spos + 1..epos]).to_string(),
                        is_tag,
                    );
                }
            }
        }
    }
    (String::new(), is_tag)
}

/// `-Y sign|find-principals|check-novalidate|verify`. `args[0]` is the
/// program name.
pub fn commit_sign_main(args: &[String]) -> i32 {
    let mut op = "";
    let mut keyfile: Option<PathBuf> = None;
    let mut principal: Option<String> = None;
    let mut sigfile: Option<PathBuf> = None;
    let mut file_arg: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-Y" => {
                i += 1;
                op = args.get(i).map(|s| s.as_str()).unwrap_or("");
            }
            "-n" | "-O" => {
                i += 1; // namespace default / ssh options, ignored
            }
            "-f" => {
                i += 1;
                keyfile = args.get(i).map(PathBuf::from);
            }
            "-I" => {
                i += 1;
                principal = args.get(i).cloned();
            }
            "-s" => {
                i += 1;
                sigfile = args.get(i).map(PathBuf::from);
            }
            _ => {
                if !arg.starts_with('-') && file_arg.is_none() {
                    file_arg = Some(PathBuf::from(arg));
                }
            }
        }
        i += 1;
    }

    let read_armored = |sigfile: &Option<PathBuf>| -> Option<Vec<u8>> {
        let path = sigfile.as_ref()?;
        let text = std::fs::read_to_string(path).ok()?;
        unarmor_ssh_signature(&text)
    };

    match op {
        "sign" => {
            let Some(keyfile) = keyfile else {
                eprintln!("Identity file not found: ");
                return 1;
            };
            if !keyfile.is_file() {
                eprintln!("Identity file not found: {}", keyfile.display());
                return 1;
            }
            let Ok(identity) = load_private_identity(&keyfile) else {
                eprintln!("Error: Could not load identity or identity has no private key");
                return 1;
            };
            let (message, sig_path) = match &file_arg {
                Some(path) if path.is_file() => match std::fs::read(path) {
                    Ok(data) => {
                        let mut sig = path.clone().into_os_string();
                        sig.push(".sig");
                        (data, Some(PathBuf::from(sig)))
                    }
                    _ => (Vec::new(), None),
                },
                _ => {
                    use std::io::Read;
                    let mut data = Vec::new();
                    let _ = std::io::stdin().read_to_end(&mut data);
                    (data, None)
                }
            };
            let rsg = pack_rsg(&identity, &message, false, &[]);
            let blob = create_ssh_signature(&identity, &rsg);
            let armored = armor_ssh_signature(&blob);
            if let Some(sig_path) = sig_path {
                if std::fs::write(&sig_path, armored).is_err() {
                    eprintln!("Error writing signature file");
                    return 1;
                }
            } else {
                print!("{armored}");
            }
            0
        }
        "find-principals" => {
            let Some(raw) = read_armored(&sigfile) else {
                eprintln!("Error: Signature file not found");
                return 1;
            };
            let Some(sig) = parse_ssh_signature(&raw) else {
                eprintln!("Error parsing SSH signature");
                return 1;
            };
            if sig.namespace != SSHSIG_NAMESPACE {
                eprintln!("Error: Namespace mismatch");
                return 1;
            }
            let Some(data) = unpack_rsg(&sig.signature_data) else {
                eprintln!("Could not determine signer identity");
                return 1;
            };
            let Some(signer) = map_get(&data.meta, "signer").and_then(value_bin) else {
                eprintln!("Could not determine signer identity");
                return 1;
            };
            println!("{}", hex_encode(signer));
            0
        }
        "check-novalidate" => {
            let Some(raw) = read_armored(&sigfile) else {
                return 1;
            };
            let Some(sig) = parse_ssh_signature(&raw) else {
                return 1;
            };
            if sig.namespace != SSHSIG_NAMESPACE {
                return 1;
            }
            if unpack_rsg(&sig.signature_data).is_some() {
                0
            } else {
                1
            }
        }
        "verify" => {
            let Some(raw) = read_armored(&sigfile) else {
                eprintln!("Error: Signature file not found");
                return 1;
            };
            use std::io::Read;
            let mut message = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut message);
            let Some(sig) = parse_ssh_signature(&raw) else {
                eprintln!("Error parsing signature");
                return 1;
            };
            let author = extract_commit_field(&message, b"author ");
            let _committer = extract_commit_field(&message, b"committer ");
            let (tagger, is_tag) = extract_commit_tagger(&message);
            if sig.namespace != SSHSIG_NAMESPACE {
                eprintln!("Invalid commit signature namespace");
                return 1;
            }
            let Some((_view, signer_hash)) = validate_rsg(&sig.signature_data, &message, None)
            else {
                eprintln!("Invalid signature");
                return 1;
            };
            let author = if is_tag { tagger } else { author };
            if author != signer_hash {
                eprintln!("Commit not signed by author <{author}>");
                return 1;
            }
            if let Some(principal) = principal {
                if principal != signer_hash {
                    eprintln!("Principal mismatch");
                    return 1;
                }
            }
            println!("Good \"git\" signature for commit, signed with Reticulum Identity key <{signer_hash}>");
            0
        }
        _ => {
            eprintln!("Error: Unknown operation: {op}");
            1
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut values = Vec::with_capacity(text.len());
    for c in text.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => break,
            _ => return None,
        };
        values.push(v);
    }
    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let n = chunk.iter().fold(0u32, |acc, v| (acc << 6) | v);
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                out.push((n >> 10) as u8);
                out.push((n >> 2) as u8);
            }
            2 => {
                out.push((n >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}
