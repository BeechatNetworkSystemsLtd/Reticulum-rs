#![cfg(feature = "python-tests")]

//! Full-stack interop with a PYTHON node in the middle routing between
//! two Rust endpoints (the drop-in-replacement proof): Rust A <->
//! Python transport <-> Rust C. Exercises announce propagation, path
//! requests, link establishment (LR relay + LRPROOF validation in the
//! PYTHON middle), and bidirectional link data through the Python node.

use std::process::Stdio;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

fn python_dir() -> String {
    std::env::var("RETICULUM_TEST_PYTHON_DIR").expect("RETICULUM_TEST_PYTHON_DIR")
}

async fn spawn_middle(listen_a: u16, forward_a: u16, listen_c: u16, forward_c: u16) -> Child {
    let script = format!("{}/tests/py-interop/middle.py", env!("CARGO_MANIFEST_DIR"));

    let mut child = Command::new("python3")
        .arg("-u")
        .arg(script)
        .arg(listen_a.to_string())
        .arg(forward_a.to_string())
        .arg(listen_c.to_string())
        .arg(forward_c.to_string())
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn middle");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("middle: {line}");
            let _ = tx.send(line).await;
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(line)) = timeout(Duration::from_millis(200), rx.recv()).await {
            if line.contains("MIDDLE-READY") {
                break;
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    child
}

/// A Rust endpoint facing the Python middle on one UDP interface.
async fn rust_endpoint(name: &str, listen: u16, forward: u16) -> Transport {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = TransportConfig::new(name, &identity).build();

    {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{listen}"),
                Some(format!("127.0.0.1:{forward}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    transport
}

#[tokio::test]
async fn link_through_python_middle_node() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    // Topology: rust-a <-> python <-> rust-c.
    // Rust A talks to the middle on 4702/4701; Rust C on 4704/4703.
    let mut middle = spawn_middle(4701, 4702, 4703, 4704).await;

    let a = rust_endpoint("rust-a", 4702, 4701).await;
    let c = rust_endpoint("rust-c", 4704, 4703).await;

    // C announces a destination; A must learn it THROUGH the Python node.
    let destination = c
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("interop", "middle"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    let mut announces = a.recv_announces().await;
    c.send_announce(&destination, Some(b"via-python")).await;
    let announce = tokio::time::timeout(Duration::from_secs(30), announces.recv())
        .await
        .expect("announce must propagate through the Python middle")
        .expect("channel");
    let desc = announce.destination.lock().await.desc;
    assert_eq!(desc.address_hash, dest_hash);

    // A links to C through the Python middle: the LR and the returning
    // LRPROOF are relayed by the Python transport node.
    let link = a.link(desc).await;
    let mut events = a.out_link_events();
    let activated = tokio::time::timeout(Duration::from_secs(30), events.recv()).await;
    assert!(
        matches!(activated, Ok(Ok(_))),
        "link must activate through the Python middle (LR relay + proof validation)"
    );

    // Bidirectional data: A -> C over the link.
    let mut received = c.in_link_events();
    let payload = b"hello through python middle";
    a.send_to_out_links(&dest_hash, payload).await;

    let event = tokio::time::timeout(Duration::from_secs(30), received.recv())
        .await
        .expect("data A->C must arrive through the Python middle")
        .expect("channel");
    match event.event {
        LinkEvent::Data(data) => assert_eq!(data.as_slice(), payload),
        other => panic!("expected data event, got {other:?}"),
    }

    // C -> A: the Python middle must route the reverse direction.
    let mut a_received = a.out_link_events();
    let reply = b"reply through python middle";

    let link_id = *link.lock().await.id();
    let response_packet = {
        let link = c.find_in_link(&link_id).await.expect("in link on C");
        let link = link.lock().await;
        link.data_packet(reply).expect("data packet")
    };
    c.send_packet(response_packet).await;

    let event = tokio::time::timeout(Duration::from_secs(30), a_received.recv())
        .await
        .expect("data C->A must arrive through the Python middle")
        .expect("channel");
    match event.event {
        LinkEvent::Data(payload) => assert_eq!(payload.as_slice(), reply),
        other => panic!("expected data event, got {other:?}"),
    }

    let _ = &mut middle;
    let _ = middle.start_kill();
    let _ = middle.wait().await;
}

#[tokio::test]
async fn python_endpoint_through_rust_middle() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    // Topology: python-a <-> rust-middle <-> python-c. The RUST node is
    // the intermediary: it must relay the Python announce, path request,
    // link request, LRPROOF and link data.
    // The Python endpoints are driven by partner.py in "announce"/"link"
    // modes.
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let middle = TransportConfig::new("rust-middle", &identity)
        .set_retransmit(true)
        .build();

    {
        let manager = middle.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4712", Some("127.0.0.1:4711"), true),
            UdpInterface::spawn,
        );
    }
    {
        let manager = middle.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4714", Some("127.0.0.1:4713"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Python C announces through the Rust middle; Python A links to it.
    // partner.py does announce-and-wait / announce-and-link.
    let script = format!(
        "{}/tests/py-interop/middle_endpoints.py",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut a_child = Command::new("python3")
        .arg("-u")
        .arg(&script)
        .arg("--role")
        .arg("initiator")
        .arg("--listen")
        .arg("4711")
        .arg("--forward")
        .arg("4712")
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python initiator");

    let mut c_child = Command::new("python3")
        .arg("-u")
        .arg(&script)
        .arg("--role")
        .arg("destination")
        .arg("--listen")
        .arg("4713")
        .arg("--forward")
        .arg("4714")
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python destination");

    let c_stderr = c_child.stderr.take().expect("c stderr");
    tokio::spawn(async move {
        let mut lines = BufReader::new(c_stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("py-c-err: {line}");
        }
    });
    let a_stderr = a_child.stderr.take().expect("a stderr");
    tokio::spawn(async move {
        let mut lines = BufReader::new(a_stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("py-a-err: {line}");
        }
    });

    let c_stdout = c_child.stdout.take().expect("c stdout");
    let (c_tx, c_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(c_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("py-c: {line}");
            let _ = c_tx.send(line).await;
        }
    });

    let a_stdout = a_child.stdout.take().expect("a stdout");
    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(a_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("py-a: {line}");
            let _ = a_tx.send(line).await;
        }
    });

    async fn wait_line(
        rx: &mut tokio::sync::mpsc::Receiver<String>,
        needle: &str,
        timeout: Duration,
    ) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if let Ok(line) = tokio::time::timeout_at(deadline, rx.recv()).await {
                match line {
                    Some(line) if line.contains(needle) => return Some(line),
                    Some(_) => continue,
                    None => return None,
                }
            }
        }
        None
    }

    // The Python destination announces; the initiator links and sends.
    let established = wait_line(&mut a_rx, "LINK-ESTABLISHED", Duration::from_secs(60)).await;
    assert!(
        established.is_some(),
        "Python link must establish through the Rust middle"
    );

    let echoed = wait_line(&mut a_rx, "ECHO-RECEIVED", Duration::from_secs(30)).await;
    assert!(
        echoed.is_some(),
        "Python echo must round-trip through the Rust middle"
    );

    let _ = c_rx;

    let _ = a_child.start_kill();
    let _ = c_child.start_kill();
    let _ = a_child.wait().await;
    let _ = c_child.wait().await;
}

/// Resources and requests over a relayed link (Rust endpoints, Python
/// transport middle). The resource engine's advertisements, requests,
/// segments and proofs are all link packets the middle must route in
/// both directions.
#[tokio::test]
async fn resource_and_request_through_python_middle() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let mut middle = spawn_middle(4751, 4752, 4753, 4754).await;
    let a = rust_endpoint("rust-a", 4752, 4751).await;
    let c = rust_endpoint("rust-c", 4754, 4753).await;

    let destination = c
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("example_utilities", "interop.resource"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;

    c.register_request_handler(&dest_hash, "echo", |ctx| {
        Some(reticulum::resource::msgpack_bin(&ctx.data))
    })
    .await;

    // Accept resources on inbound links as they appear.
    tokio::spawn({
        let c = unsafe { &*(&c as *const Transport) };
        async move {
            let mut events = c.in_link_events();
            while let Ok(event) = events.recv().await {
                if let LinkEvent::Activated = event.event {
                    c.set_resource_strategy(event.id, reticulum::resource::ResourceStrategy::All)
                        .await;
                }
            }
        }
    });

    let mut announces = a.recv_announces().await;
    c.send_announce(&destination, None).await;
    let announce = tokio::time::timeout(Duration::from_secs(30), announces.recv())
        .await
        .expect("announce through python middle")
        .expect("channel");
    let desc = announce.destination.lock().await.desc;
    assert_eq!(desc.address_hash, dest_hash);

    let link = a.link(desc).await;
    let mut events = a.out_link_events();
    let activated = tokio::time::timeout(Duration::from_secs(30), events.recv())
        .await
        .expect("link must activate through the middle")
        .expect("channel");
    assert!(matches!(activated.event, LinkEvent::Activated));

    // Request/response through the relayed link.
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
    let response = a
        .request(&link, "echo", payload.as_slice())
        .await
        .expect("request sent");
    let response_data = a
        .await_request_response(response, Duration::from_secs(30))
        .await
        .expect("response through python middle");
    assert_eq!(response_data.as_slice(), payload.as_slice());

    // Resource transfer through the relayed link.
    let resource_payload: Vec<u8> = (0..80_000u32).map(|i| (i % 249) as u8).collect();
    let expected_sha = {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&resource_payload);
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    a.send_resource_with_options(
        &link,
        resource_payload,
        reticulum::resource::ResourceOptions {
            auto_compress: false,
            ..Default::default()
        },
    )
    .await
    .expect("send resource");

    let mut resource_events = c.resource_events().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == reticulum::resource::ResourceStatus::Complete {
            if let Some(data) = event.data {
                received = Some(data);
                break;
            }
        }
    }
    let received = received.expect("resource through python middle");
    let received_sha = {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&received);
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert_eq!(received_sha, expected_sha);

    let _ = &mut middle;
    let _ = middle.start_kill();
    let _ = middle.wait().await;
}

/// Python request endpoints through a Rust transport middle: path
/// request, link request, request and response all relayed by Rust.
#[tokio::test]
async fn python_request_through_rust_middle() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let middle = TransportConfig::new("rust-middle", &identity)
        .set_retransmit(true)
        .build();

    {
        let manager = middle.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4772", Some("127.0.0.1:4771"), true),
            UdpInterface::spawn,
        );
    }
    {
        let manager = middle.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4774", Some("127.0.0.1:4773"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let script = format!("{}/tests/py-interop/partner.py", env!("CARGO_MANIFEST_DIR"));
    let python_dir = python_dir();

    let mut c_child = tokio::process::Command::new("python3")
        .arg("-u")
        .arg(&script)
        .arg("--config")
        .arg(partner_config(4773, 4774).to_str().unwrap())
        .arg("--mode")
        .arg("request-server")
        .arg("--size")
        .arg("0")
        .arg("--timeout")
        .arg("60")
        .env("PYTHONPATH", &python_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python request server");

    let (c_tx, mut c_rx) = tokio::sync::mpsc::channel(16);
    let c_stdout = c_child.stdout.take().expect("c stdout");
    tokio::spawn(async move {
        let mut lines = BufReader::new(c_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("py-c: {line}");
            let _ = c_tx.send(line).await;
        }
    });

    let dest_line = wait_for(&mut c_rx, "destination ", Duration::from_secs(20))
        .await
        .expect("python request server announced");
    let hex: String = dest_line
        .split_whitespace()
        .rev()
        .find(|w| w.len() == 32 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("destination hash")
        .to_string();

    let mut a_child = tokio::process::Command::new("python3")
        .arg("-u")
        .arg(&script)
        .arg("--config")
        .arg(partner_config(4771, 4772).to_str().unwrap())
        .arg("--mode")
        .arg("request-client")
        .arg("--size")
        .arg("5000")
        .arg("--destination")
        .arg(&hex)
        .arg("--timeout")
        .arg("60")
        .env("PYTHONPATH", &python_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python request client");

    let (a_tx, mut a_rx) = tokio::sync::mpsc::channel(16);
    let a_stdout = a_child.stdout.take().expect("a stdout");
    tokio::spawn(async move {
        let mut lines = BufReader::new(a_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("py-a: {line}");
            let _ = a_tx.send(line).await;
        }
    });

    let requesting = wait_for(&mut a_rx, "requesting sha ", Duration::from_secs(30))
        .await
        .expect("python client requested through the rust middle");
    let expected: String = requesting
        .split_whitespace()
        .last()
        .expect("sha")
        .to_string();

    let response = wait_for(&mut a_rx, "response sha ", Duration::from_secs(30))
        .await
        .expect("python client received response through the rust middle");
    let actual: String = response.split_whitespace().last().expect("sha").to_string();
    assert_eq!(expected, actual);

    let _ = a_child.start_kill();
    let _ = c_child.start_kill();
    let _ = a_child.wait().await;
    let _ = c_child.wait().await;
}

async fn wait_for(
    rx: &mut tokio::sync::mpsc::Receiver<String>,
    needle: &str,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if let Ok(line) = tokio::time::timeout_at(deadline, rx.recv()).await {
            match line {
                Some(line) if line.contains(needle) => return Some(line),
                Some(_) => continue,
                None => return None,
            }
        }
    }
    None
}

/// Write a partner config directory whose UDP interface forwards to the
/// given port.
fn partner_config(listen: u16, forward: u16) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rns-partner-{listen}-{forward}"));
    let config_dir = dir.join("config");
    std::fs::create_dir_all(config_dir.join("storage")).expect("config dirs");
    std::fs::write(
        config_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = No\n\n[interfaces]\n  [[Endpoint]]\n    type = UDPInterface\n    enabled = yes\n    listen_ip = 127.0.0.1\n    listen_port = {listen}\n    forward_ip = 127.0.0.1\n    forward_port = {forward}\n"
        ),
    )
    .expect("write config");
    config_dir
}
