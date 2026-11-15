//! Split-resource (multi-segment) transfers above MAX_EFFICIENT_SIZE
//! (Python `Resource` segmentation): all segments must be advertised and
//! delivered, hashes computed per segment.

use std::time::Duration;

use rand_core::OsRng;

use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::resource::{ResourceOptions, ResourceStatus, MAX_EFFICIENT_SIZE};
use reticulum::transport::{Transport, TransportConfig};

async fn udp_pair(name: &str, pa: u16, pb: u16) -> (Transport, Transport) {
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let a = TransportConfig::new(format!("{name}-a"), &identity_a).build();
    let b = TransportConfig::new(format!("{name}-b"), &identity_b).build();

    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{pa}"),
                Some(format!("127.0.0.1:{pb}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{pb}"),
                Some(format!("127.0.0.1:{pa}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    (a, b)
}

#[tokio::test]
async fn split_resource_transfers_all_segments() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();
    let (a, b) = udp_pair("split", 4522, 4523).await;

    let destination = b
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("split", "receiver"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    b.set_accepts_links(&dest_hash, true).await;
    // The destination lives on b; b announces, a receives and links.
    let mut announces = a.recv_announces().await;
    b.send_announce(&destination, None).await;
    let announce = tokio::time::timeout(Duration::from_secs(10), announces.recv())
        .await
        .expect("announce timeout")
        .expect("channel");
    let desc = announce.destination.lock().await.desc;

    let link = a.link(desc).await;
    let mut out_events = a.out_link_events();
    let _ = tokio::time::timeout(Duration::from_secs(10), out_events.recv()).await;

    // The receiver must accept advertised resources on its inbound link
    // (Python `link.set_resource_strategy(ACCEPT_APP/ALL)`).
    let link_id = *link.lock().await.id();
    b.set_resource_strategy(link_id, reticulum::resource::ResourceStrategy::All)
        .await;

    // A split transfer with metadata, deliberately disabling compression.
    let payload: Vec<u8> = (0..(MAX_EFFICIENT_SIZE + 256 * 1024))
        .map(|i| (i % 251) as u8)
        .collect();
    let metadata = vec![
        0x81, 0xa4, b'n', b'a', b'm', b'e', 0xc4, 0x0b, b'p', b'a', b'y', b'l', b'o', b'a', b'd',
        b'.', b'b', b'i', b'n',
    ];

    let mut events = a.resource_events().await;
    let mut receiver_events = b.resource_events().await;
    a.send_resource_with_options(
        &link,
        payload.clone(),
        ResourceOptions {
            auto_compress: false,
            metadata: Some(metadata.clone()),
            ..ResourceOptions::default()
        },
    )
    .await
    .expect("send");

    let mut segments_completed = 0;
    let expected = 2;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    while segments_completed < expected && tokio::time::Instant::now() < deadline {
        let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv()).await else {
            break;
        };
        if matches!(event.status, ResourceStatus::Complete) {
            segments_completed += 1;
        }
    }

    assert!(
        segments_completed >= expected,
        "expected {expected} segment completions for a 1.25 MiB payload, got {segments_completed}"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut final_data = None;
    let mut final_metadata = None;
    while tokio::time::Instant::now() < deadline {
        let Ok(Ok(event)) = tokio::time::timeout_at(deadline, receiver_events.recv()).await else {
            break;
        };
        if event.status == ResourceStatus::Complete && event.data.is_some() {
            final_data = event.data;
            final_metadata = event.metadata;
            break;
        }
    }
    assert_eq!(final_data.as_deref(), Some(payload.as_slice()));
    assert_eq!(final_metadata, Some(metadata));
}

#[tokio::test]
async fn split_file_transfers_all_segments() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();
    let (a, b) = udp_pair("split-file", 4544, 4545).await;

    let destination = b
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("split", "file"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    b.set_accepts_links(&dest_hash, true).await;
    let mut announces = a.recv_announces().await;
    b.send_announce(&destination, None).await;
    let announce = tokio::time::timeout(Duration::from_secs(10), announces.recv())
        .await
        .expect("announce timeout")
        .expect("channel");
    let desc = announce.destination.lock().await.desc;

    let link = a.link(desc).await;
    let mut out_events = a.out_link_events();
    let _ = tokio::time::timeout(Duration::from_secs(10), out_events.recv()).await;

    let link_id = *link.lock().await.id();
    b.set_resource_strategy(link_id, reticulum::resource::ResourceStrategy::All)
        .await;

    let payload: Vec<u8> = (0..(MAX_EFFICIENT_SIZE + 32 * 1024))
        .map(|i| (i % 251) as u8)
        .collect();
    let path = std::env::temp_dir().join(format!(
        "reticulum-resource-test-{}-split",
        std::process::id()
    ));
    std::fs::write(&path, &payload).expect("write file");

    let mut events = a.resource_events().await;
    let mut receiver_events = b.resource_events().await;
    a.send_resource_from_path(
        &link,
        &path,
        ResourceOptions {
            auto_compress: false,
            ..ResourceOptions::default()
        },
    )
    .await
    .expect("send file");

    let mut segments_completed = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    while segments_completed < 2 && tokio::time::Instant::now() < deadline {
        let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv()).await else {
            break;
        };
        if matches!(event.status, ResourceStatus::Complete) {
            segments_completed += 1;
        }
    }
    assert!(
        segments_completed >= 2,
        "expected both segments of a file above MAX_EFFICIENT_SIZE, got {segments_completed}"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut final_data = None;
    while tokio::time::Instant::now() < deadline {
        let Ok(Ok(event)) = tokio::time::timeout_at(deadline, receiver_events.recv()).await else {
            break;
        };
        if event.status == ResourceStatus::Complete && event.data.is_some() {
            final_data = event.data;
            break;
        }
    }
    let _ = std::fs::remove_file(&path);
    assert_eq!(final_data.as_deref(), Some(payload.as_slice()));
}
