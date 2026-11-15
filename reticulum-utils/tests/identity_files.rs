//! Identity file persistence tests (Phase 1.1 / 7.4):
//! hex round-trip, Python raw-key round-trip, rnid generate → daemon load
//! (restart stability).

use std::path::PathBuf;

use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum_utils::common::{
    identity_from_raw_keys, load_or_create_private_identity, load_private_identity,
    save_private_identity,
};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rn-identity-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn hex_round_trip() {
    let dir = temp_dir("hex");
    let path = dir.join("identity");
    let identity = PrivateIdentity::new_from_rand(OsRng);

    save_private_identity(&path, &identity).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content.len(), 128);

    let loaded = load_private_identity(&path).unwrap();
    assert_eq!(
        loaded.address_hash().to_hex_string(),
        identity.address_hash().to_hex_string()
    );
    assert_eq!(loaded.to_hex_string(), identity.to_hex_string());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn python_raw_key_format_round_trip() {
    // Python Identity.to_file writes 64 raw key bytes (X25519 private key ‖
    // Ed25519 signing key) in the same order as our hex format.
    let dir = temp_dir("raw");
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let hex_string = identity.to_hex_string();
    let mut raw = Vec::with_capacity(64);
    for pair in hex_string.as_bytes().chunks(2) {
        raw.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    let path = dir.join("identity.rid");
    std::fs::write(&path, &raw).unwrap();

    let loaded = load_private_identity(&path).unwrap();
    assert_eq!(loaded.to_hex_string(), hex_string);
    assert_eq!(
        identity_from_raw_keys(&raw).unwrap().to_hex_string(),
        hex_string
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_identity_file_is_rejected() {
    let dir = temp_dir("corrupt");
    let path = dir.join("identity");
    std::fs::write(&path, "not-an-identity").unwrap();
    assert!(load_private_identity(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rnid_generate_then_daemon_restart_keeps_identity_stable() {
    // `rn id -g <path>` generates and saves; the daemon loads the same file
    // on every start, so the instance identity (and all destinations derived
    // from it) must stay stable across restarts.
    let config_dir = temp_dir("restart");
    let identity_path = config_dir.join("identity");

    // First "rn id -g" run.
    let exit = reticulum_utils::rnid::run(reticulum_utils::rnid::IdOptions {
        generate: Some(identity_path.clone()),
        identity: None,
        public: false,
        no_save: false,
        ..Default::default()
    })
    .expect("rnid generate");
    assert_eq!(exit, 0);

    // First daemon start: load-or-create must load, not create.
    let (first, created) = load_or_create_private_identity(&identity_path).unwrap();
    assert!(!created);

    // Simulated restarts.
    for _ in 0..3 {
        let (again, created) = load_or_create_private_identity(&identity_path).unwrap();
        assert!(!created);
        assert_eq!(
            again.address_hash().to_hex_string(),
            first.address_hash().to_hex_string()
        );
    }

    // `rn id -i` can inspect the same file.
    let exit = reticulum_utils::rnid::run(reticulum_utils::rnid::IdOptions {
        generate: None,
        identity: Some(identity_path.display().to_string()),
        public: false,
        no_save: false,
        ..Default::default()
    })
    .expect("rnid inspect");
    assert_eq!(exit, 0);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[test]
fn rncp_identity_persists_per_config_dir() {
    let config_dir = temp_dir("rncp-id");
    let path = config_dir.join("storage/identities/rncp");
    let (first, created) = load_or_create_private_identity(&path).unwrap();
    assert!(created);
    assert!(path.exists());
    let (second, created) = load_or_create_private_identity(&path).unwrap();
    assert!(!created);
    assert_eq!(
        first.address_hash().to_hex_string(),
        second.address_hash().to_hex_string()
    );
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[cfg(unix)]
#[test]
fn private_identity_writes_are_owner_only_even_for_existing_files() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("permissions");
    let paths = [
        dir.join("identity"),
        dir.join("storage/identities/rnsh"),
        dir.join("storage/identities/rnx"),
        dir.join("storage/identities/rncp"),
        dir.join("utility.rid"),
    ];
    let identity = PrivateIdentity::new_from_rand(OsRng);

    for path in paths {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, b"replace me").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        save_private_identity(&path, &identity).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "{} must remain private",
            path.display()
        );
    }

    let _ = std::fs::remove_dir_all(dir);
}

/// Location of a Python Reticulum checkout for interop tests.
///
/// `RETICULUM_TEST_PYTHON_DIR` (the same var CI sets in
/// `.github/workflows/ci.yml`) overrides the default: a `Reticulum`
/// checkout sitting next to this repository (`<workspace>/../Reticulum`).
fn python_repo() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("RETICULUM_TEST_PYTHON_DIR") {
        return std::path::PathBuf::from(path);
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Reticulum")
}

fn rn_cmd(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rn"))
        .args(args)
        .output()
        .expect("rn")
}

fn python_rnid(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    let repo = python_repo();
    std::process::Command::new("python3")
        .arg(repo.join("RNS/Utilities/rnid.py"))
        .args(args)
        .current_dir(home)
        .env("PYTHONPATH", &repo)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONPYCACHEPREFIX", home)
        .env("HOME", home)
        .output()
        .expect("python3")
}

fn line_after<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing {prefix} in {text}"))
        .trim()
}

#[test]
fn base32_export_matches_bytes_python_rnid_reads() {
    let dir = temp_dir("b32-py");
    let id_path = dir.join("identity");
    let generated = rn_cmd(&["id", "-g", id_path.to_str().unwrap()]);
    assert!(
        generated.status.success(),
        "generate stderr {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let hex_file = std::fs::read_to_string(&id_path).unwrap();
    let hex_file = hex_file.trim();
    assert_eq!(hex_file.len(), 128);

    let exported = rn_cmd(&["id", "-i", id_path.to_str().unwrap(), "-X", "-B"]);
    let stdout = String::from_utf8(exported.stdout.clone()).unwrap();
    assert!(
        exported.status.success(),
        "export stderr {} stdout {stdout}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let base32 = line_after(&stdout, "Private Identity Keys : ");
    assert_eq!(
        base32.len(),
        104,
        "base32 of a 64-byte key is 104 characters"
    );
    assert!(base32.ends_with('='));

    let python = python_rnid(&dir, &["-M", base32, "-p", "-P"]);
    let py_out = String::from_utf8(python.stdout.clone()).unwrap();
    assert!(
        python.status.success(),
        "python stderr {} stdout {py_out}",
        String::from_utf8_lossy(&python.stderr)
    );
    let private_hex = line_after(&py_out, "Private Key   : ");
    assert_eq!(private_hex, hex_file);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sign_and_validate_agree_with_python_rnid() {
    let dir = temp_dir("sig-py");
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let raw = identity.to_bytes();
    let id_path = dir.join("identity.rid");
    std::fs::write(&id_path, raw).unwrap();
    let message = dir.join("payload.bin");
    let payload = b"rnid-interop-payload";
    std::fs::write(&message, payload).unwrap();

    let signed = rn_cmd(&[
        "id",
        "-i",
        id_path.to_str().unwrap(),
        "-s",
        message.to_str().unwrap(),
    ]);
    let signed_out = String::from_utf8_lossy(&signed.stdout);
    assert!(
        signed.status.success(),
        "sign stderr {} stdout {signed_out}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let rsg_path = dir.join("payload.bin.rsg");
    let rsg = std::fs::read(&rsg_path).unwrap();
    assert!(rsg.len() > 64);
    let signature =
        reticulum::identity::Signature::from_bytes(&<[u8; 64]>::try_from(&rsg[..64]).unwrap());
    assert!(identity
        .as_identity()
        .verify(&rsg[64..], &signature)
        .is_ok());

    let python = python_rnid(
        &dir,
        &[
            "-i",
            id_path.to_str().unwrap(),
            "-V",
            message.to_str().unwrap(),
        ],
    );
    let py_out = String::from_utf8(python.stdout.clone()).unwrap();
    assert!(
        python.status.success(),
        "python validate stderr {} stdout {py_out}",
        String::from_utf8_lossy(&python.stderr)
    );
    assert!(
        py_out.contains("Signature is valid"),
        "python did not accept the signature bytes: {py_out}"
    );
    let signer = identity.address_hash().to_hex_string();
    assert!(
        py_out.contains(&signer),
        "python report did not name the signing identity {signer}: {py_out}"
    );

    let other = dir.join("from-python.bin");
    std::fs::write(&other, b"python-signed").unwrap();
    let python_sign = python_rnid(
        &dir,
        &[
            "-i",
            id_path.to_str().unwrap(),
            "-s",
            other.to_str().unwrap(),
        ],
    );
    let py_sign = String::from_utf8_lossy(&python_sign.stdout);
    assert!(
        python_sign.status.success(),
        "python sign stderr {} stdout {py_sign}",
        String::from_utf8_lossy(&python_sign.stderr)
    );
    let python_rsg = std::fs::read(dir.join("from-python.bin.rsg")).unwrap();
    assert!(python_rsg.len() > 64);
    let python_sig = reticulum::identity::Signature::from_bytes(
        &<[u8; 64]>::try_from(&python_rsg[..64]).unwrap(),
    );
    assert!(
        identity
            .as_identity()
            .verify(&python_rsg[64..], &python_sig)
            .is_ok(),
        "rust could not verify the signature bytes python wrote"
    );
    let checked = rn_cmd(&[
        "id",
        "-i",
        id_path.to_str().unwrap(),
        "-V",
        other.to_str().unwrap(),
    ]);
    assert!(
        checked.status.success(),
        "validate python signature stderr {} stdout {}",
        String::from_utf8_lossy(&checked.stderr),
        String::from_utf8_lossy(&checked.stdout)
    );

    let hashed = rn_cmd(&[
        "id",
        "-i",
        id_path.to_str().unwrap(),
        "-H",
        "example.aspect",
    ]);
    let hash_out = String::from_utf8(hashed.stdout).unwrap();
    assert!(hashed.status.success(), "{hash_out}");
    let shown = line_after(
        &hash_out,
        "The example.aspect destination for this Identity is ",
    );
    let shown = shown.trim_matches(|ch| ch == '<' || ch == '>');
    let script = dir.join("hash_check.py");
    std::fs::write(
        &script,
        "import sys\nimport RNS\nident = RNS.Identity(create_keys=False)\nident.load_private_key(open(sys.argv[1], 'rb').read())\nprint(RNS.Destination.hash_from_name_and_identity('example.aspect', ident.hash).hex())\nprint(RNS.Destination.hash_from_name_and_identity('solo', ident.hash).hex())\nprint(ident.hexhash)\n",
    )
    .unwrap();
    let py_hash = std::process::Command::new("python3")
        .arg(&script)
        .arg(&id_path)
        .current_dir(&dir)
        .env("PYTHONPATH", python_repo())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONPYCACHEPREFIX", &dir)
        .env("HOME", &dir)
        .output()
        .unwrap();
    let py_hash_out = String::from_utf8(py_hash.stdout).unwrap();
    assert!(
        py_hash.status.success(),
        "{}",
        String::from_utf8_lossy(&py_hash.stderr)
    );
    let mut lines = py_hash_out.lines();
    let aspect = lines.next().unwrap();
    let solo = lines.next().unwrap();
    let hexhash = lines.next().unwrap();
    assert_eq!(shown, aspect);
    assert!(hash_out.contains(&format!("<example.aspect.{hexhash}:{aspect}>")));

    let solo_out = rn_cmd(&["id", "-i", id_path.to_str().unwrap(), "-H", "solo"]);
    let solo_text = String::from_utf8(solo_out.stdout).unwrap();
    let solo_shown = line_after(&solo_text, "The solo destination for this Identity is ");
    assert_eq!(solo_shown.trim_matches(|ch| ch == '<' || ch == '>'), solo);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn encrypt_roundtrip_matches_python_rnid_framing() {
    let dir = temp_dir("rfe-py");
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let id_path = dir.join("identity.rid");
    std::fs::write(&id_path, identity.to_bytes()).unwrap();
    let plain = dir.join("plain.bin");
    let plaintext = vec![7u8; 32];
    std::fs::write(&plain, &plaintext).unwrap();

    let encrypted = rn_cmd(&[
        "id",
        "-i",
        id_path.to_str().unwrap(),
        "-e",
        plain.to_str().unwrap(),
    ]);
    assert!(
        encrypted.status.success(),
        "encrypt stderr {}",
        String::from_utf8_lossy(&encrypted.stderr)
    );
    let rfe = dir.join("plain.bin.rfe");
    assert!(rfe.is_file());
    let python = python_rnid(
        &dir,
        &[
            "-i",
            id_path.to_str().unwrap(),
            "-d",
            rfe.to_str().unwrap(),
            "-w",
            dir.join("from-rust.bin").to_str().unwrap(),
        ],
    );
    let py_out = String::from_utf8_lossy(&python.stdout);
    assert!(
        python.status.success(),
        "python decrypt stderr {} stdout {py_out}",
        String::from_utf8_lossy(&python.stderr)
    );
    assert_eq!(std::fs::read(dir.join("from-rust.bin")).unwrap(), plaintext);

    let py_plain = dir.join("py-plain.bin");
    std::fs::write(&py_plain, b"python-plain").unwrap();
    let py_enc = python_rnid(
        &dir,
        &[
            "-i",
            id_path.to_str().unwrap(),
            "-e",
            py_plain.to_str().unwrap(),
            "-w",
            dir.join("py.rfe").to_str().unwrap(),
        ],
    );
    assert!(
        py_enc.status.success(),
        "python encrypt stderr {}",
        String::from_utf8_lossy(&py_enc.stderr)
    );
    let decrypted = rn_cmd(&[
        "id",
        "-i",
        id_path.to_str().unwrap(),
        "-d",
        dir.join("py.rfe").to_str().unwrap(),
        "-w",
        dir.join("from-python.bin").to_str().unwrap(),
    ]);
    assert!(
        decrypted.status.success(),
        "decrypt stderr {} stdout {}",
        String::from_utf8_lossy(&decrypted.stderr),
        String::from_utf8_lossy(&decrypted.stdout)
    );
    assert_eq!(
        std::fs::read(dir.join("from-python.bin")).unwrap(),
        b"python-plain"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
