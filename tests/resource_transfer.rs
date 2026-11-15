//! Resource transfer tests: unit tests for wire formats (against Python
//! golden vectors) and end-to-end loopback transfers over a local link.

use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use rand_core::OsRng;
use reticulum::destination::link::{Link, LinkEvent};
use reticulum::destination::DestinationName;
use reticulum::hash::{AddressHash, Hash};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::resource::manager::RequestEvent;
use reticulum::resource::{
    self, advertisement::ResourceAdvertisement, msgpack_bin, pack_response, request_id,
    unpack_request, unpack_response, RequestAllow, RequestHandlerConfig, RequestOptions,
    RequestResponse, ResourceOptions, ResourceStatus, ResourceStrategy,
};
use reticulum::transport::{Transport, TransportConfig};

fn setup_logging() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn advertisement_pack_matches_python() {
    let expected = load_vectors()["adv1"].clone();

    let adv = ResourceAdvertisement {
        transfer_size: 1234,
        data_size: 1000,
        parts: 4,
        hash: Hash::new((0u8..32).collect::<Vec<u8>>().try_into().unwrap()),
        random_hash: [0xAA; 4],
        original_hash: Hash::new((32u8..64).collect::<Vec<u8>>().try_into().unwrap()),
        segment_index: 1,
        total_segments: 1,
        request_id: None,
        flags: 0,
        hashmap: vec![1, 2, 3, 4],
    };

    let packed = adv.pack();
    assert_eq!(hex(&packed), expected);

    let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack");
    assert_eq!(unpacked.transfer_size, 1234);
    assert_eq!(unpacked.data_size, 1000);
    assert_eq!(unpacked.parts, 4);
    assert_eq!(unpacked.hash, adv.hash);
    assert_eq!(unpacked.random_hash, adv.random_hash);
    assert_eq!(unpacked.original_hash, adv.original_hash);
    assert_eq!(unpacked.flags, 0);
    assert_eq!(unpacked.hashmap, vec![1, 2, 3, 4]);
    assert!(unpacked.request_id.is_none());
}

#[test]
fn advertisement_pack_with_flags_matches_python() {
    let expected = load_vectors()["adv2"].clone();

    let adv = ResourceAdvertisement {
        transfer_size: 1234,
        data_size: 1000,
        parts: 4,
        hash: Hash::new((0u8..32).collect::<Vec<u8>>().try_into().unwrap()),
        random_hash: [0xAA; 4],
        original_hash: Hash::new((32u8..64).collect::<Vec<u8>>().try_into().unwrap()),
        segment_index: 1,
        total_segments: 1,
        request_id: Some(AddressHash::new([0x0f; 16])),
        flags: 0x3f,
        hashmap: vec![1, 2, 3, 4],
    };

    let packed = adv.pack();
    assert_eq!(hex(&packed), expected);

    let unpacked = ResourceAdvertisement::unpack(&packed).expect("unpack");
    assert_eq!(unpacked.flags, 0x3f);
    assert!(unpacked.encrypted());
    assert!(unpacked.compressed());
    assert!(unpacked.split());
    // with all bits set, both request and response flags are set
    assert!(unpacked.is_request());
    assert!(unpacked.is_response());
    assert!(unpacked.has_metadata());
    assert_eq!(unpacked.request_id, Some(AddressHash::new([0x0f; 16])));
}

fn load_vectors() -> std::collections::HashMap<String, String> {
    let raw = std::fs::read_to_string("tests/fixtures_msgpack.json").expect("fixtures");
    serde_json::from_str(&raw).expect("fixture json")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn request_and_response_wire_formats_match_python() {
    let vectors = load_vectors();
    let golden_req = vectors["req"].as_str();
    let golden_resp = vectors["resp"].as_str();

    let req_bytes = hex_to_bytes(golden_req);
    let (time, path_hash, data) = unpack_request(&req_bytes).expect("unpack request");
    assert!((time - 12345.678).abs() < 0.001);
    assert_eq!(path_hash.as_slice(), &[0x11; 16]);
    assert_eq!(data, b"payload");

    let resp_bytes = hex_to_bytes(golden_resp);
    let (rid, response) = unpack_response(&resp_bytes).expect("unpack response");
    assert_eq!(rid.as_slice(), &[0x22; 16]);
    assert_eq!(response, b"response-data");

    // `unpack_response` unwraps binary elements to their contents, so a
    // byte-for-byte roundtrip re-wraps them as msgpack bins first.
    let re_packed = pack_response(&rid, &msgpack_bin(&response));
    assert_eq!(hex(&re_packed), golden_resp);

    // Request id is the truncated hash of the packed request
    let rid = request_id(&req_bytes);
    assert_eq!(rid.as_slice().len(), 16);
}

#[test]
fn hashmap_update_wire_format_matches_python() {
    let golden = load_vectors()["hmu"].clone();
    let mut packed = Vec::new();
    rmp::encode::write_array_len(&mut packed, 2).unwrap();
    rmp::encode::write_uint(&mut packed, 3).unwrap();
    rmp::encode::write_bin(&mut packed, &[0x33; 8]).unwrap();
    assert_eq!(hex(&packed), golden);
}

#[test]
fn compression_roundtrip() {
    // Highly repetitive data compresses; random data does not.
    let repetitive = vec![0xAB; 10000];
    let (compressed, did_compress) =
        resource::maybe_compress(&repetitive, true, resource::AUTO_COMPRESS_MAX_SIZE);
    if cfg!(feature = "bz2") {
        assert!(did_compress);
        assert!(compressed.len() < repetitive.len());
        let decompressed = resource::decompress(&compressed, 1_000_000).expect("decompress");
        assert_eq!(decompressed, repetitive);

        let random: Vec<u8> = (0..1000u32).map(|i| (i * 7919 % 256) as u8).collect();
        let (unchanged, did_not) =
            resource::maybe_compress(&random, true, resource::AUTO_COMPRESS_MAX_SIZE);
        // random-ish data may or may not compress; whatever the result it
        // must round-trip
        if did_not {
            let back = resource::decompress(&unchanged, 1_000_000).expect("decompress");
            assert_eq!(back, random);
        } else {
            assert_eq!(unchanged.len(), random.len());
        }
    } else {
        assert!(!did_compress);
        assert_eq!(compressed, repetitive);
    }
}

/// Two transports connected over loopback UDP with an active link.
async fn connected_pair(
    server_port: u16,
    client_port: u16,
) -> (Transport, Transport, Arc<Mutex<Link>>) {
    let server_identity = PrivateIdentity::new_from_rand(OsRng);
    let server = TransportConfig::new("srv", &server_identity).build();
    let client = TransportConfig::new("cli", &PrivateIdentity::new_from_rand(OsRng)).build();

    server.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{server_port}"),
            Some(format!("127.0.0.1:{client_port}")),
            false,
        ),
        UdpInterface::spawn,
    );
    client.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{client_port}"),
            Some(format!("127.0.0.1:{server_port}")),
            false,
        ),
        UdpInterface::spawn,
    );

    let destination = server
        .add_destination(server_identity, DestinationName::new("test", "resources"))
        .await;
    let hash = destination.lock().await.desc.address_hash;

    // Subscribe before announcing so the event cannot slip past the
    // receiver; a slow retry covers interface-worker startup races under
    // parallel test load.
    let mut announces = client.recv_announces().await;
    server.send_announce(&destination, None).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let desc = loop {
        assert!(tokio::time::Instant::now() < deadline, "no announce");
        match tokio::time::timeout(Duration::from_secs(3), announces.recv()).await {
            Ok(Ok(event)) => {
                if event.destination.lock().await.desc.address_hash == hash {
                    break event.destination.lock().await.desc;
                }
            }
            Ok(Err(err)) => panic!("error waiting for announce: {err}"),
            Err(_) => server.send_announce(&destination, None).await,
        }
    };

    let mut client_events = client.out_link_events();
    let link = client.link(desc).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "link inactive");
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if let LinkEvent::Activated = event.event {
            break;
        }
    }

    // wait for the server to register the inbound link
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let link_id = *link.lock().await.id();
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "server link missing"
        );
        if server.find_in_link(&link_id).await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    (server, client, link)
}

#[tokio::test]
async fn resource_transfer_roundtrip() {
    setup_logging();
    let (server, client, link) = connected_pair(4311, 4312).await;

    // Accept all resources on the server side of the link
    let link_id = *link.lock().await.id();
    server
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;

    let mut resource_events = server.resource_events().await;

    let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    client
        .send_resource(&link, payload.clone())
        .await
        .expect("send resource");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                received = Some(data);
                break;
            }
        }
    }
    let received = received.expect("resource did not complete");
    assert_eq!(received, payload);

    // Wait for the client to see the completion (proof validation)
    let mut client_events = client.resource_events().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "sender completion missing"
        );
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            break;
        }
    }
}

#[tokio::test]
async fn resource_transfer_tiny() {
    let (server, client, link) = connected_pair(4321, 4322).await;
    let link_id = *link.lock().await.id();
    server
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;

    let mut resource_events = server.resource_events().await;
    let payload = b"tiny resource payload".to_vec();
    client
        .send_resource(&link, payload.clone())
        .await
        .expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                received = Some(data);
                break;
            }
        }
    }
    assert_eq!(received.expect("tiny resource"), payload);
}

#[tokio::test]
async fn resource_transfer_with_metadata() {
    let (server, client, link) = connected_pair(4331, 4332).await;
    let link_id = *link.lock().await.id();
    server
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;

    let mut resource_events = server.resource_events().await;
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 249) as u8).collect();
    let metadata = b"some metadata".to_vec();
    let options = ResourceOptions {
        metadata: Some(metadata.clone()),
        ..Default::default()
    };
    client
        .send_resource_with_options(&link, payload.clone(), options)
        .await
        .expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                got = Some((data, event.metadata));
                break;
            }
        }
    }
    let (data, meta) = got.expect("resource with metadata");
    assert_eq!(data, payload);
    assert_eq!(meta, Some(metadata));
}

#[tokio::test]
async fn request_response_roundtrip() {
    let (server, client, link) = connected_pair(4341, 4342).await;

    // Register a request handler on the server destination
    let destination = server
        .get_in_destination(&link.lock().await.destination().address_hash)
        .await
        .expect("destination");

    let dest_hash = destination.lock().await.desc.address_hash;
    server
        .register_request_handler(&dest_hash, "echo", |ctx| {
            Some(reticulum::resource::msgpack_bin(&ctx.data))
        })
        .await;

    // Send a request and await the response
    let rid = client
        .request(&link, "echo", b"hello request")
        .await
        .expect("request");

    let response = client
        .await_request_response(rid, Duration::from_secs(10))
        .await;
    assert_eq!(response, Some(b"hello request".to_vec()));
}

#[tokio::test]
async fn request_response_large_resource_backed() {
    let (server, client, link) = connected_pair(4351, 4352).await;

    let destination = server
        .get_in_destination(&link.lock().await.destination().address_hash)
        .await
        .expect("destination");
    let dest_hash = destination.lock().await.desc.address_hash;

    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    let response_payload = payload.clone();

    server
        .register_request_handler(&dest_hash, "bulk", move |_ctx| {
            Some(msgpack_bin(&response_payload))
        })
        .await;

    let rid = client
        .request(&link, "bulk", b"send-me-data")
        .await
        .expect("request");

    let response = client
        .await_request_response(rid, Duration::from_secs(60))
        .await;
    assert_eq!(response, Some(payload));
}

#[tokio::test]
async fn split_response_can_be_awaited_after_completion_event() {
    let (server, client, link) = connected_pair(4353, 4354).await;

    let destination = server
        .get_in_destination(&link.lock().await.destination().address_hash)
        .await
        .expect("destination");
    let dest_hash = destination.lock().await.desc.address_hash;
    let payload: Vec<u8> = (0..(resource::MAX_EFFICIENT_SIZE + 4096) as u32)
        .map(|i| (i % 251) as u8)
        .collect();
    let response_payload = payload.clone();
    server
        .register_request_handler(&dest_hash, "split-bulk", move |_ctx| {
            Some(msgpack_bin(&response_payload))
        })
        .await;

    let mut request_events = client.request_events().await;
    let rid = client
        .request(&link, "split-bulk", b"late-await")
        .await
        .expect("request");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let event = tokio::time::timeout_at(deadline, request_events.recv())
            .await
            .expect("response event timeout")
            .expect("request event channel");
        if matches!(event.event, RequestEvent::Response { request_id, .. } if request_id == rid) {
            break;
        }
    }

    let response = client
        .await_request_response(rid, Duration::from_secs(10))
        .await;
    assert_eq!(response, Some(payload));
}

#[tokio::test]
async fn resource_transfer_reject_oversized() {
    let (server, client, link) = connected_pair(4361, 4362).await;
    // Default strategy is None: advertisements are ignored
    let mut resource_events = server.resource_events().await;
    let payload = vec![0u8; 1000];
    client.send_resource(&link, payload).await.expect("send");

    // no acceptance event should arrive
    let result = tokio::time::timeout(Duration::from_secs(2), resource_events.recv()).await;
    if let Ok(Ok(event)) = result {
        // any event other than a completion is fine
        assert_ne!(event.status, ResourceStatus::Complete);
    }
}

/// Cancelling two multi-megabyte loopback transfers concurrently floods
/// the UDP socket buffers and starves other tests' control packets, so the
/// cancel tests share a lock.
static CANCEL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn incompressible(size: usize, seed: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size);
    let mut state = seed;
    while payload.len() < size {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        payload.extend_from_slice(&state.to_le_bytes());
    }
    payload
}

#[tokio::test]
async fn sender_cancel_fails_both_ends_of_a_transfer() {
    setup_logging();
    let _guard = CANCEL_TEST_LOCK.lock().await;
    let (server, client, link) = connected_pair(4591, 4592).await;

    let link_id = *link.lock().await.id();
    server
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;

    let mut server_events = server.resource_events().await;
    let mut client_events = client.resource_events().await;

    // A megabyte of incompressible data keeps the transfer in flight
    // while the sender cancels it.
    let payload = incompressible(1024 * 1024, 0x1234_5678);
    let hash = client
        .send_resource(&link, payload)
        .await
        .expect("send resource");

    // Give the receiver a moment to accept and start requesting parts,
    // then cancel as the initiator (Python `Resource.cancel` sends
    // RESOURCE_ICL).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut transferring = false;
    while tokio::time::Instant::now() < deadline && !transferring {
        let event = tokio::time::timeout(Duration::from_millis(500), server_events.recv())
            .await
            .ok()
            .and_then(|result| result.ok())
            .expect("channel");
        if event.hash == hash
            && matches!(
                event.status,
                ResourceStatus::Transferring | ResourceStatus::Advertised
            )
        {
            transferring = true;
        }
    }
    assert!(transferring, "transfer never started");

    client
        .cancel_resource(&link_id, &hash)
        .await
        .expect("cancel resource");

    // The sender observes the local cancellation.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "sender never saw the cancellation"
        );
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.hash == hash && event.status == ResourceStatus::Failed {
            break;
        }
    }

    // The receiver learns about the cancellation over RESOURCE_ICL.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "receiver never saw the cancellation"
        );
        let event = tokio::time::timeout_at(deadline, server_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.hash == hash && event.status == ResourceStatus::Failed {
            break;
        }
    }
}

#[tokio::test]
async fn receiver_cancel_fails_sender_transfer() {
    setup_logging();
    let _guard = CANCEL_TEST_LOCK.lock().await;
    let (server, client, link) = connected_pair(4593, 4594).await;

    let link_id = *link.lock().await.id();
    server
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;

    let mut server_events = server.resource_events().await;
    let mut client_events = client.resource_events().await;

    let payload = incompressible(1024 * 1024, 0x8765_4321);
    let hash = client
        .send_resource(&link, payload)
        .await
        .expect("send resource");

    // Wait for the incoming transfer to be underway, then cancel as the
    // receiver (Python `Resource.cancel` sends RESOURCE_RCL from the
    // receiver).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut transferring = false;
    while tokio::time::Instant::now() < deadline && !transferring {
        let event = tokio::time::timeout(Duration::from_millis(500), server_events.recv())
            .await
            .ok()
            .and_then(|result| result.ok())
            .expect("channel");
        if event.hash == hash
            && matches!(
                event.status,
                ResourceStatus::Transferring | ResourceStatus::Advertised
            )
        {
            transferring = true;
        }
    }
    assert!(transferring, "transfer never started");

    server
        .cancel_resource(&link_id, &hash)
        .await
        .expect("cancel resource");

    // The receiver marked its own side failed.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "receiver never saw its own cancellation"
        );
        let event = tokio::time::timeout_at(deadline, server_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.hash == hash && event.status == ResourceStatus::Failed {
            break;
        }
    }

    // The sender receives RESOURCE_RCL and stops advertising/transferring.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "sender never saw the receiver cancellation"
        );
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.hash == hash && event.status == ResourceStatus::Rejected {
            break;
        }
    }

    // Cancelling an unknown resource is an error, not a panic.
    let unknown = Hash::new([0xAB; 32]);
    assert!(client.cancel_resource(&link_id, &unknown).await.is_err());
}

#[tokio::test]
async fn interface_stats_for_link_resolves_the_links_interface() {
    setup_logging();
    let (server, client, link) = connected_pair(4595, 4596).await;
    let link_id = *link.lock().await.id();

    // The outbound side resolves the next-hop interface of the path.
    let stats = client
        .interface_stats_for_link(link_id)
        .await
        .expect("link interface stats");
    assert_eq!(stats.kind, "UdpInterface");
    assert!(stats.online);

    // The inbound side resolves the receiving interface.
    let stats = server
        .interface_stats_for_link(link_id)
        .await
        .expect("link interface stats");
    assert_eq!(stats.kind, "UdpInterface");

    // Unknown links report nothing instead of guessing.
    assert!(client
        .interface_stats_for_link(AddressHash::new([0x0e; 16]))
        .await
        .is_none());
}

async fn dest_hash(server: &Transport, link: &Arc<Mutex<Link>>) -> AddressHash {
    let destination = server
        .get_in_destination(&link.lock().await.destination().address_hash)
        .await
        .expect("destination");
    let hash = destination.lock().await.desc.address_hash;
    hash
}

#[tokio::test]
async fn request_response_emits_progress() {
    let (server, client, link) = connected_pair(4811, 4812).await;
    let dest_hash = dest_hash(&server, &link).await;

    // Incompressible so the response stays a multi-part resource. A
    // payload that bz2 shrinks under the link MDU would be one packet
    // and would never report resource progress.
    let payload = incompressible(48 * 1024, 0x0A1_1CE);
    let response_payload = payload.clone();
    server
        .register_request_handler(&dest_hash, "progress", move |_ctx| {
            Some(msgpack_bin(&response_payload))
        })
        .await;

    let mut request_events = client.request_events().await;
    let rid = client
        .request(&link, "progress", b"go")
        .await
        .expect("request");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut saw_progress = false;
    let mut response = None;
    while tokio::time::Instant::now() < deadline && response.is_none() {
        match tokio::time::timeout_at(deadline, request_events.recv()).await {
            Ok(Ok(event)) => match event.event {
                RequestEvent::Progress {
                    request_id,
                    progress,
                } if request_id == rid && progress > 0.0 => {
                    saw_progress = true;
                }
                RequestEvent::Response {
                    request_id, data, ..
                } if request_id == rid => {
                    response = Some(data);
                }
                RequestEvent::Failed { request_id } if request_id == rid => {
                    panic!("progress request failed");
                }
                _ => {}
            },
            // The broadcast retains 64 events; a fast transfer overruns it.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(err)) => panic!("request event channel closed: {err}"),
            Err(_) => break,
        }
    }
    assert!(saw_progress, "expected RequestEvent::Progress above 0");
    assert_eq!(response.as_deref(), Some(payload.as_slice()));
}

#[tokio::test]
async fn request_allow_list_requires_an_identified_peer() {
    let (server, client, link) = connected_pair(4821, 4822).await;
    let dest_hash = dest_hash(&server, &link).await;
    let allowed = PrivateIdentity::new_from_rand(OsRng);
    let stranger = PrivateIdentity::new_from_rand(OsRng);

    server
        .register_request_handler_with_config(
            &dest_hash,
            "secret",
            RequestHandlerConfig {
                allow: RequestAllow::List,
                allowed_list: vec![*allowed.address_hash()],
                ..Default::default()
            },
            |_ctx| Some(RequestResponse::Element(msgpack_bin(b"ok"))),
        )
        .await;
    server
        .register_request_handler_with_config(
            &dest_hash,
            "other",
            RequestHandlerConfig {
                allow: RequestAllow::List,
                allowed_list: vec![*stranger.address_hash()],
                ..Default::default()
            },
            |_ctx| Some(RequestResponse::Element(msgpack_bin(b"no"))),
        )
        .await;
    server
        .register_request_handler_with_config(
            &dest_hash,
            "closed",
            RequestHandlerConfig {
                allow: RequestAllow::None,
                ..Default::default()
            },
            |_ctx| Some(RequestResponse::Element(msgpack_bin(b"no"))),
        )
        .await;

    let denied = client
        .request(&link, "secret", b"x")
        .await
        .expect("request");
    assert!(client
        .await_request_response(denied, Duration::from_millis(800))
        .await
        .is_none());

    let packet = link.lock().await.identify(&allowed).expect("identify");
    client.send_packet(packet).await;

    let link_id = *link.lock().await.id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "peer never identified"
        );
        if let Some(inbound) = server.find_in_link(&link_id).await {
            if inbound.lock().await.remote_identity().is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let rid = client
        .request(&link, "secret", b"x")
        .await
        .expect("request");
    let response = client
        .await_request_response(rid, Duration::from_secs(5))
        .await;
    assert_eq!(response, Some(b"ok".to_vec()));

    // A hash that is not the identified peer, and ALLOW_NONE, stay silent
    // after the same identify. A link accepts one identity.
    for path in ["other", "closed"] {
        let rid = client.request(&link, path, b"x").await.expect("request");
        assert!(
            client
                .await_request_response(rid, Duration::from_millis(800))
                .await
                .is_none(),
            "{path} responded"
        );
    }
}

#[tokio::test]
async fn file_backed_resource_roundtrip() {
    let (server, client, link) = connected_pair(4831, 4832).await;
    let link_id = *link.lock().await.id();
    server
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;
    let mut resource_events = server.resource_events().await;
    let mut sender_events = client.resource_events().await;

    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let path = std::env::temp_dir().join(format!(
        "reticulum-resource-test-{}-file",
        std::process::id()
    ));
    std::fs::write(&path, &payload).expect("write file");
    let file_hash = client
        .send_resource_from_path(&link, &path, ResourceOptions::default())
        .await
        .expect("send file");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                received = Some(data);
                break;
            }
        }
    }
    assert_eq!(received.as_deref(), Some(payload.as_slice()));
    let _ = std::fs::remove_file(&path);

    // The next transfer is queued until this one is proven. Wait for the
    // sender so the stream is advertised immediately.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "sender did not finish the file"
        );
        let event = tokio::time::timeout_at(deadline, sender_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.hash == file_hash && event.status == ResourceStatus::Complete {
            break;
        }
    }

    let stream_payload = b"streamed-not-seekable".to_vec();
    let reader = OwnedReader {
        data: stream_payload.clone(),
        pos: 0,
    };
    client
        .send_resource_from_read(&link, reader, ResourceOptions::default())
        .await
        .expect("send stream");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete
            && event.data.as_deref() == Some(stream_payload.as_slice())
        {
            received = event.data;
            break;
        }
    }
    assert_eq!(received.as_deref(), Some(stream_payload.as_slice()));
}

#[tokio::test]
async fn file_response_is_not_msgpack_wrapped() {
    let (server, client, link) = connected_pair(4833, 4834).await;
    let dest_hash = dest_hash(&server, &link).await;

    let payload = vec![0x5A; 16 * 1024];
    let metadata = b"file-meta".to_vec();
    let path = std::env::temp_dir().join(format!(
        "reticulum-resource-test-{}-response",
        std::process::id()
    ));
    std::fs::write(&path, &payload).expect("write file");
    let handler_path = path.clone();
    let handler_meta = metadata.clone();
    server
        .register_request_handler_with_config(
            &dest_hash,
            "file",
            RequestHandlerConfig::default(),
            move |_ctx| {
                Some(RequestResponse::File {
                    path: handler_path.clone(),
                    metadata: Some(handler_meta.clone()),
                })
            },
        )
        .await;

    let mut request_events = client.request_events().await;
    let rid = client
        .request(&link, "file", b"get")
        .await
        .expect("request");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got = None;
    while tokio::time::Instant::now() < deadline && got.is_none() {
        match tokio::time::timeout_at(deadline, request_events.recv()).await {
            Ok(Ok(event)) => match event.event {
                RequestEvent::Response {
                    request_id,
                    data,
                    metadata,
                } if request_id == rid => {
                    got = Some((data, metadata));
                }
                RequestEvent::Failed { request_id } if request_id == rid => {
                    panic!("file response failed");
                }
                _ => {}
            },
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(err)) => panic!("request event channel closed: {err}"),
            Err(_) => break,
        }
    }
    let _ = std::fs::remove_file(&path);
    let (data, meta) = got.expect("file response");
    assert_eq!(data, payload);
    assert_eq!(meta, Some(metadata));
    // A wrapped `[request_id, bytes]` element would unpack. The file
    // bytes are the response itself.
    assert!(unpack_response(&data).is_none());
}

/// Reads are counted. Seeks, including the length probe, are not: Python
/// discovers a file's size with `seek` and only then reads a segment.
struct CountingReader {
    len: u64,
    pos: u64,
    read_bytes: Arc<AtomicUsize>,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min((self.len - self.pos) as usize);
        buf[..n].fill(0);
        self.pos += n as u64;
        self.read_bytes.fetch_add(n, Ordering::SeqCst);
        Ok(n)
    }
}

impl Seek for CountingReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.len + delta as u64
                } else {
                    self.len.saturating_sub(delta.unsigned_abs())
                }
            }
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.pos + delta as u64
                } else {
                    self.pos.saturating_sub(delta.unsigned_abs())
                }
            }
        };
        self.pos = next;
        Ok(self.pos)
    }
}

struct OwnedReader {
    data: Vec<u8>,
    pos: usize,
}

impl Read for OwnedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let n = (self.data.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[tokio::test]
async fn file_backed_transfer_reads_one_segment_before_advertise() {
    let (_server, client, link) = connected_pair(4835, 4836).await;
    // Default strategy ignores the advertisement, so the sender cannot be
    // pulled into segment 2 before this assertion runs.
    let total = resource::MAX_EFFICIENT_SIZE + 4096;
    let read_bytes = Arc::new(AtomicUsize::new(0));
    let reader = CountingReader {
        len: total as u64,
        pos: 0,
        read_bytes: read_bytes.clone(),
    };
    client
        .send_resource_from_reader(
            &link,
            reader,
            ResourceOptions {
                auto_compress: false,
                ..Default::default()
            },
        )
        .await
        .expect("send reader");

    let read = read_bytes.load(Ordering::SeqCst);
    assert_eq!(read, resource::MAX_EFFICIENT_SIZE);
    assert!(read < total);
}

#[tokio::test]
async fn per_request_timeout_ignores_a_late_response() {
    let (server, client, link) = connected_pair(4841, 4842).await;
    let dest_hash = dest_hash(&server, &link).await;
    server
        .register_async_request_handler(&dest_hash, "slow", |_ctx| async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Some(msgpack_bin(b"late"))
        })
        .await;

    let mut request_events = client.request_events().await;
    let rid = client
        .request_with_options(
            &link,
            "slow",
            b"x",
            RequestOptions {
                timeout: Some(0.4),
                max_response_size: None,
            },
        )
        .await
        .expect("request");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut saw_failed = false;
    let mut saw_response = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, request_events.recv()).await {
            Ok(Ok(event)) => match event.event {
                RequestEvent::Failed { request_id } if request_id == rid => {
                    saw_failed = true;
                }
                RequestEvent::Response { request_id, .. } if request_id == rid => {
                    saw_response = true;
                    break;
                }
                _ => {}
            },
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            _ => break,
        }
    }
    assert!(saw_failed, "request did not fail when its timeout elapsed");
    assert!(!saw_response, "late response was delivered");
}

#[tokio::test]
async fn per_request_timeout_ignores_a_late_resource_response() {
    let (server, client, link) = connected_pair(4871, 4872).await;
    let dest_hash = dest_hash(&server, &link).await;
    // Larger than the link MDU and incompressible, so the response is a
    // resource rather than a single RESPONSE packet.
    let payload = incompressible(48 * 1024, 0x0A1_1CF);
    server
        .register_async_request_handler(&dest_hash, "slowres", move |_ctx| {
            let payload = payload.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                Some(msgpack_bin(&payload))
            }
        })
        .await;

    let mut request_events = client.request_events().await;
    let rid = client
        .request_with_options(
            &link,
            "slowres",
            b"x",
            RequestOptions {
                timeout: Some(0.4),
                max_response_size: None,
            },
        )
        .await
        .expect("request");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut saw_failed = false;
    let mut saw_response = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, request_events.recv()).await {
            Ok(Ok(event)) => match event.event {
                RequestEvent::Failed { request_id } if request_id == rid => {
                    saw_failed = true;
                }
                RequestEvent::Response { request_id, .. } if request_id == rid => {
                    saw_response = true;
                    break;
                }
                _ => {}
            },
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            _ => break,
        }
    }
    assert!(
        saw_failed,
        "resource request did not fail when its timeout elapsed"
    );
    assert!(!saw_response, "late resource response was delivered");
}

#[tokio::test]
async fn per_request_max_response_size_is_enforced() {
    let (server, client, link) = connected_pair(4851, 4852).await;
    let dest_hash = dest_hash(&server, &link).await;
    server
        .register_request_handler(&dest_hash, "sized", |_ctx| Some(msgpack_bin(b"hello")))
        .await;

    // bin8 of 5 bytes is reported as 5 (`len(packb(response)) - 2`).
    let too_big = client
        .request_with_options(
            &link,
            "sized",
            b"x",
            RequestOptions {
                timeout: None,
                max_response_size: Some(4),
            },
        )
        .await
        .expect("request");
    assert!(client
        .await_request_response(too_big, Duration::from_secs(3))
        .await
        .is_none());

    let fits = client
        .request_with_options(
            &link,
            "sized",
            b"x",
            RequestOptions {
                timeout: None,
                max_response_size: Some(16),
            },
        )
        .await
        .expect("request");
    assert_eq!(
        client
            .await_request_response(fits, Duration::from_secs(5))
            .await,
        Some(b"hello".to_vec())
    );
}

#[tokio::test]
async fn auto_compress_limit_is_the_original_input_size() {
    let (server, client, link) = connected_pair(4861, 4862).await;
    let link_id = *link.lock().await.id();
    server
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;

    let payload = vec![0xAB; 8 * 1024];
    let mut client_events = client.resource_events().await;
    client
        .send_resource_with_options(
            &link,
            payload.clone(),
            ResourceOptions {
                auto_compress: true,
                auto_compress_limit: Some(10),
                ..Default::default()
            },
        )
        .await
        .expect("send");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut limited = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(adv) = event.advertisement {
                limited = Some(adv.compressed());
                break;
            }
        }
    }
    // The segment is 8 KiB, but Python compares the original input to the
    // integer limit, so this transfer must stay uncompressed.
    assert_eq!(limited, Some(false));

    client
        .send_resource_with_options(&link, payload, ResourceOptions::default())
        .await
        .expect("send");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut default_compressed = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, client_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(adv) = event.advertisement {
                default_compressed = Some(adv.compressed());
                break;
            }
        }
    }
    assert_eq!(default_compressed, Some(cfg!(feature = "bz2")));
}
