//! rngit loopback test: one instance creates a repository and pushes a
//! commit, the other fetches it back — all over the same request/resource
//! wire path the `git-remote-rns` helper drives (link → identify →
//! `/git/create`, `/git/list`, `/git/push`, `/git/fetch` with a
//! resource-carried git bundle response).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use reticulum_utils::common::{build_tool_transport, ToolTransportOptions};
use reticulum_utils::rngit;
use tokio_util::sync::CancellationToken;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rn-rngit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_udp_config(dir: &Path, listen_port: u16, forward_port: u16) {
    write_udp_config_n(dir, &[(listen_port, forward_port)]);
}

fn write_udp_config_n(dir: &Path, ifaces: &[(u16, u16)]) {
    std::fs::create_dir_all(dir).unwrap();
    let mut config = String::from("[reticulum]\nshare_instance = false\n");
    for (i, (listen, forward)) in ifaces.iter().enumerate() {
        config.push_str(&format!(
            "\n[[interfaces]]\nname = \"Loopback UDP {i}\"\ntype = \"UDPInterface\"\nenabled = true\n\
             listen_ip = \"127.0.0.1\"\nlisten_port = {listen}\n\
             forward_ip = \"127.0.0.1\"\nforward_port = {forward}\n"
        ));
    }
    std::fs::write(dir.join("config.toml"), config).unwrap();
}

fn git(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git_out(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[tokio::test]
async fn create_push_fetch_over_udp_loopback() {
    let _ = env_logger::try_init();
    let server_rns = temp_dir("server-rns");
    let node_dir = temp_dir("node");
    let group_dir = temp_dir("repos");
    let client_a_rns = temp_dir("client-a-rns");
    let client_a_dir = temp_dir("client-a");
    let client_b_rns = temp_dir("client-b-rns");
    let client_b_dir = temp_dir("client-b");
    let client_c_rns = temp_dir("client-c-rns");
    let client_c_dir = temp_dir("client-c");
    let work_a = temp_dir("work-a");
    let work_b = temp_dir("work-b");
    let work_c = temp_dir("work-c");

    // The node listens on 4771 (client A pair), 4774 (client B pair) and
    // 4776 (client C pair — the git-remote-rns helper process).
    write_udp_config_n(&server_rns, &[(4771, 4772), (4774, 4773), (4776, 4775)]);
    write_udp_config(&client_a_rns, 4772, 4771);
    write_udp_config(&client_b_rns, 4773, 4774);
    write_udp_config(&client_c_rns, 4775, 4776);

    // rngit node config: one repository group, everyone may read/write/create.
    std::fs::write(
        node_dir.join("config"),
        format!("[repositories]\nmain = {}\n", group_dir.display()),
    )
    .unwrap();
    std::fs::write(
        PathBuf::from(format!("{}.allowed", group_dir.display())),
        "rw:all\nc:all\n",
    )
    .unwrap();

    let node_transport = Arc::new(
        build_tool_transport(ToolTransportOptions {
            config_dir: &server_rns,
            instance_name: "rngit-node",
            enable_transport: false,
            udp_loopback: None,
        })
        .await,
    );
    let shutdown = CancellationToken::new();
    let destination =
        rngit::serve_with_transport(&node_transport, &node_dir, Some(shutdown.clone()))
            .await
            .expect("node serve");
    let remote = format!("rns://{}/main/repo.git", destination.to_hex_string());

    // Instance A: create the repository, commit a file, push it.
    let client_a = rngit::RemoteClient::connect(
        &rngit::ClientOptions {
            rngit_config_dir: client_a_dir.clone(),
            rns_config_dir: client_a_rns.clone(),
            ..Default::default()
        },
        &remote,
    )
    .await
    .expect("client A connect");

    client_a
        .create_repository("main/repo.git")
        .await
        .expect("create repository");

    let file_contents = b"hello over reticulum\n";
    std::fs::write(work_a.join("hello.txt"), file_contents).unwrap();
    assert!(git(&work_a, &["init", "-b", "main"]));
    assert!(git(&work_a, &["config", "user.email", "a@rngit"]));
    assert!(git(&work_a, &["config", "user.name", "A"]));
    assert!(git(&work_a, &["add", "hello.txt"]));
    assert!(git(&work_a, &["commit", "-m", "initial"]));
    let sha = git_out(&work_a, &["rev-parse", "HEAD"]).expect("commit sha");

    // Discover remote refs (empty) then push the branch.
    let mut client_a = client_a;
    client_a
        .list_refs("main/repo.git", true)
        .await
        .expect("list for push");
    let results = client_a
        .push_refs(
            &[(
                "refs/heads/main".to_string(),
                "refs/heads/main".to_string(),
                false,
            )],
            "main/repo.git",
            &work_a,
            Duration::from_secs(60),
        )
        .await;
    for (reference, result) in &results {
        assert!(result.is_ok(), "push {reference} failed: {result:?}");
    }
    client_a.close().await;

    // Instance B: list + fetch over the same message path.
    let mut client_b = rngit::RemoteClient::connect(
        &rngit::ClientOptions {
            rngit_config_dir: client_b_dir.clone(),
            rns_config_dir: client_b_rns.clone(),
            ..Default::default()
        },
        &remote,
    )
    .await
    .expect("client B connect");
    client_b
        .list_refs("main/repo.git", false)
        .await
        .expect("list refs");
    assert_eq!(
        client_b
            .remote_refs
            .get("refs/heads/main")
            .map(String::as_str),
        Some(sha.as_str()),
        "remote refs must advertise the pushed commit"
    );

    assert!(git(&work_b, &["init", "-b", "main"]));
    client_b
        .fetch_refs(
            &[(sha.clone(), "refs/heads/main".to_string())],
            "main/repo.git",
            &work_b,
            Duration::from_secs(60),
        )
        .await
        .expect("fetch refs");
    client_b.close().await;

    // The fetched commit must exist locally and contain the same file.
    let out = Command::new("git")
        .args(["cat-file", "blob", &format!("{sha}:hello.txt")])
        .current_dir(&work_b)
        .output()
        .expect("git cat-file");
    assert!(out.status.success(), "blob must exist after fetch");
    assert_eq!(
        out.stdout, file_contents,
        "fetched file contents must match"
    );

    let helper_dir = temp_dir("helpers");
    let rn_binary = env!("CARGO_BIN_EXE_rn");
    #[cfg(unix)]
    std::os::unix::fs::symlink(rn_binary, helper_dir.join("git-remote-rns")).unwrap();
    #[cfg(not(unix))]
    std::fs::copy(rn_binary, helper_dir.join("git-remote-rns")).unwrap();

    assert!(git(&work_c, &["init", "-b", "main"]));
    assert!(git(&work_c, &["remote", "add", "rns", &remote]));
    let old_path = std::env::var("PATH").unwrap_or_default();
    // NOTE: `#[tokio::test]` is a current-thread runtime; a blocking
    // `std::process::Command` would freeze the node's tasks for the whole
    // duration of the fetch. Spawn the git subprocess on the runtime.
    let fetch = tokio::process::Command::new("git")
        .args(["fetch", "rns"])
        .current_dir(&work_c)
        .env("PATH", format!("{}:{}", helper_dir.display(), old_path))
        .env("RNGIT_CONFIG", &client_c_dir)
        .env("RNS_CONFIG", &client_c_rns)
        .output()
        .await
        .expect("git fetch rns");
    assert!(
        fetch.status.success(),
        "git fetch through git-remote-rns failed: {}",
        String::from_utf8_lossy(&fetch.stderr)
    );
    let out = Command::new("git")
        .args(["cat-file", "blob", "FETCH_HEAD:hello.txt"])
        .current_dir(&work_c)
        .output()
        .expect("git cat-file");
    assert!(out.status.success(), "blob must exist after git fetch");
    assert_eq!(
        out.stdout, file_contents,
        "file fetched via git-remote-rns must match"
    );

    shutdown.cancel();
}
