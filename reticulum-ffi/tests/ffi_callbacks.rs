//! FFI callback coverage: an `AppReconciler` implemented in Rust receives
//! updates through `listen_for_updates`, `stop_listening` stops delivery,
//! and dispatching every `AppAction` produces the documented updates.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flume::Sender;
use reticulum_ffi::{
    AppAction, AppAudioPolicy, AppReconciler, AppSharedInstanceAccessConfig, AppState, AppUpdate,
    AudioBridge, FfiApp, InterfaceConfig, LxmfDeliveryMethod, LxmfMessageFields, NodeStatus,
    SharedInstanceAddress,
};

struct CollectingReconciler {
    tx: Sender<AppUpdate>,
    reconciles: Arc<AtomicU64>,
}

impl AppReconciler for CollectingReconciler {
    fn reconcile(&self, update: AppUpdate) {
        self.reconciles.fetch_add(1, Ordering::SeqCst);
        let _ = self.tx.send(update);
    }
}

fn wait_for(rx: &flume::Receiver<AppUpdate>, seconds: u64, predicate: impl Fn(&AppUpdate) -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(update) => {
                if predicate(&update) {
                    return;
                }
            }
            Err(flume::RecvTimeoutError::Timeout) => continue,
            Err(flume::RecvTimeoutError::Disconnected) => panic!("update channel closed"),
        }
    }
    panic!("timed out waiting for FFI update");
}

fn test_dir(tag: &str) -> String {
    let dir = format!("/tmp/reticulum-ffi-cb-{tag}-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn started_app(tag: &str) -> Arc<FfiApp> {
    let app = FfiApp::new(test_dir(tag));
    app.dispatch(AppAction::Start {
        transport_enabled: false,
        identity_address: None,
    });
    // Poll state until the node reports Running.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if matches!(app.state().status, NodeStatus::Running { .. }) {
            return app;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("node did not start");
}

#[test]
fn reconciler_receives_updates_and_stop_listening_halts_delivery() {
    let app = started_app("listen");
    let (tx, rx) = flume::unbounded();
    let reconciles = Arc::new(AtomicU64::new(0));
    app.listen_for_updates(Box::new(CollectingReconciler {
        tx: tx.clone(),
        reconciles: reconciles.clone(),
    }));

    // Dispatch produces a full-state update for the reconciler.
    app.dispatch(AppAction::CreateDestination {
        app_name: "ffi.test".into(),
        aspect: "listen".into(),
    });
    wait_for(
        &rx,
        20,
        |u| matches!(u, AppUpdate::FullState(s) if !s.destinations.is_empty()),
    );
    assert!(reconciles.load(Ordering::SeqCst) > 0);

    // Stopping the listener halts update delivery.
    app.stop_listening();
    let before = reconciles.load(Ordering::SeqCst);
    app.dispatch(AppAction::CreateDestination {
        app_name: "ffi.test".into(),
        aspect: "after-stop".into(),
    });
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(
        reconciles.load(Ordering::SeqCst),
        before,
        "reconciler still received updates after stop_listening"
    );

    // A restarted listener receives updates again.
    let (tx2, rx2) = flume::unbounded();
    let reconciles2 = Arc::new(AtomicU64::new(0));
    app.listen_for_updates(Box::new(CollectingReconciler {
        tx: tx2,
        reconciles: reconciles2,
    }));
    app.dispatch(AppAction::CreateDestination {
        app_name: "ffi.test".into(),
        aspect: "restarted".into(),
    });
    wait_for(
        &rx2,
        20,
        |u| matches!(u, AppUpdate::FullState(s) if s.destinations.len() >= 2),
    );
    app.dispatch(AppAction::Stop);
}

/// A trivial audio bridge used to exercise the audio action surface.
struct NoopAudioBridge;

impl AudioBridge for NoopAudioBridge {
    fn read_frames(&self, _codec: String, _max_frames: u32) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn write_frames(&self, _codec: String, _frames: Vec<Vec<u8>>) {}
}

#[test]
fn dispatch_exercises_each_app_action_surface() {
    let app = started_app("surface");
    let (tx, rx) = flume::unbounded();
    app.listen_for_updates(Box::new(CollectingReconciler {
        tx,
        reconciles: Arc::new(AtomicU64::new(0)),
    }));
    app.set_audio_bridge(Box::new(NoopAudioBridge));

    let destination = loop {
        app.dispatch(AppAction::CreateDestination {
            app_name: "ffi.surface".into(),
            aspect: "dest".into(),
        });
        let state: AppState = app.state();
        if let Some(destination) = state.destinations.first() {
            break destination.address_hash.clone();
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    // Interfaces.
    app.dispatch(AppAction::AddInterface {
        name: "ffi-local".into(),
        config: InterfaceConfig::LocalServer {
            address: SharedInstanceAddress::Tcp { port: 0 },
        },
        ifac: None,
        enabled: true,
    });
    wait_for(
        &rx,
        20,
        |u| matches!(u, AppUpdate::InterfaceAdded { name, .. } if name == "ffi-local"),
    );

    // Identities and destinations.
    app.dispatch(AppAction::CreateIdentity {
        name: "ffi-id".into(),
    });
    wait_for(&rx, 20, |u| matches!(u, AppUpdate::IdentityCreated { .. }));
    app.dispatch(AppAction::Announce {
        destination_hash: destination.clone(),
        app_data: Vec::new(),
    });

    // LXMF surface (announce + send with the transport-encryption field).
    app.dispatch(AppAction::AnnounceLxmfDelivery);
    app.dispatch(AppAction::SendLxmfMessage {
        destination_hash: destination.clone(),
        fields: LxmfMessageFields {
            text: Some("ffi hello".into()),
            title: None,
            image: None,
            audio: None,
            files: Vec::new(),
            icon_appearance: None,
            telemetry: None,
            reactions: Vec::new(),
            reply_to: None,
            reply_quote: None,
            renderer: None,
            custom_data: None,
            custom_type: None,
        },
        method: LxmfDeliveryMethod::Opportunistic,
        stamp_cost: None,
        include_ticket: false,
        transport_encryption: Some("curve25519".into()),
    });
    // The send attempt surfaces as a message state change (send fails
    // without a path; the update still documents the attempt).
    wait_for(&rx, 30, |u| {
        matches!(u, AppUpdate::MessageStateChanged { .. })
            || matches!(u, AppUpdate::SendFailed { .. })
            || matches!(u, AppUpdate::FullState(s) if !s.messages.is_empty())
    });

    // Audio + call policy surface.
    app.dispatch(AppAction::SetAudioBridge);
    app.dispatch(AppAction::SetAudioPolicy {
        policy: AppAudioPolicy {
            warning_latency_ms: 500,
            max_consecutive_failures: 3,
            min_quality: None,
            quality_grace_ticks: 2,
        },
    });

    // Resources (unknown resource errors surface as a toast state).
    app.dispatch(AppAction::CancelResource {
        hash: "ab".repeat(32),
    });
    wait_for(
        &rx,
        20,
        |u| matches!(u, AppUpdate::FullState(s) if s.toast.is_some()),
    );

    // Shared instance with an access config.
    app.dispatch(AppAction::StartSharedInstance {
        address: SharedInstanceAddress::Tcp { port: 0 },
        access: Some(AppSharedInstanceAccessConfig {
            allow: vec!["ffi-client".into()],
            required_token: Some(b"ffi-token".to_vec()),
            max_clients: Some(4),
        }),
    });
    wait_for(
        &rx,
        20,
        |u| matches!(u, AppUpdate::FullState(s) if s.shared_instance.hosting),
    );
    app.dispatch(AppAction::StopSharedInstance);

    // Ticks start and stop cleanly.
    app.dispatch(AppAction::StartNetworkTick { interval_ms: 200 });
    wait_for(&rx, 20, |u| matches!(u, AppUpdate::NetworkTick(_)));
    app.dispatch(AppAction::StopNetworkTick);

    // Discovery and propagation-node announcements run without a running
    // listener (they emit nothing harmful and must not panic).
    app.dispatch(AppAction::StartDiscovery {
        required_value: 8,
        autoconnect: false,
    });
    app.dispatch(AppAction::StopDiscovery);
    app.dispatch(AppAction::AnnounceLxmfPropagationNode);
    app.dispatch(AppAction::AnnounceCallEndpoint);
    app.dispatch(AppAction::ClearToast);

    std::thread::sleep(Duration::from_millis(300));
    app.stop_listening();
    app.dispatch(AppAction::Stop);
    // The listener is stopped, so poll the shared state directly.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if matches!(app.state().status, NodeStatus::Stopped) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(matches!(app.state().status, NodeStatus::Stopped));
}

#[test]
fn ffi_app_can_restart_after_stop() {
    let app = started_app("restart");
    app.dispatch(AppAction::Stop);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if matches!(app.state().status, NodeStatus::Stopped) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(matches!(app.state().status, NodeStatus::Stopped));

    // Restart on the same instance.
    app.dispatch(AppAction::Start {
        transport_enabled: false,
        identity_address: None,
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if matches!(app.state().status, NodeStatus::Running { .. }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        matches!(app.state().status, NodeStatus::Running { .. }),
        "node did not restart"
    );
    app.dispatch(AppAction::Stop);
}

/// A reconciler that stops its own update stream from inside the callback,
/// mirroring mobile apps that tear down the listener on a lifecycle event.
struct SelfStoppingReconciler {
    app: Arc<FfiApp>,
    tx: Sender<AppUpdate>,
    stopped_from_callback: Arc<std::sync::atomic::AtomicBool>,
    stop_returned: Arc<std::sync::atomic::AtomicBool>,
}

impl AppReconciler for SelfStoppingReconciler {
    fn reconcile(&self, update: AppUpdate) {
        let _ = self.tx.send(update);
        if !self.stopped_from_callback.swap(true, Ordering::SeqCst) {
            // Calling stop_listening on the app whose callback we are
            // currently running must neither panic nor hang; the flag is
            // only set once the call has returned.
            self.app.stop_listening();
            self.stop_returned.store(true, Ordering::SeqCst);
        }
    }
}

#[test]
fn stop_listening_from_inside_a_callback_does_not_deadlock() {
    let app = started_app("self-stop");
    let (tx, rx) = flume::unbounded();
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
    app.listen_for_updates(Box::new(SelfStoppingReconciler {
        app: app.clone(),
        tx,
        stopped_from_callback: stopped.clone(),
        stop_returned: stop_returned.clone(),
    }));

    // Produce updates until the callback has stopped its own listener and
    // stop_listening has returned (a self-join would panic or hang here).
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !stop_returned.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "stop_listening never returned from inside the callback"
        );
        app.dispatch(AppAction::GetCapabilities);
        std::thread::sleep(Duration::from_millis(100));
    }

    // The listener exits on its own within one receive timeout, and no
    // further updates are delivered after the self-stop.
    std::thread::sleep(Duration::from_millis(400));
    while rx.recv_timeout(Duration::from_millis(1)).is_ok() {}
    app.dispatch(AppAction::GetCapabilities);
    app.dispatch(AppAction::GetCapabilities);
    assert!(
        rx.recv_timeout(Duration::from_millis(700)).is_err(),
        "updates were still delivered after stop_listening from a callback"
    );

    // A listener can be started again afterwards from the main thread.
    let (tx2, rx2) = flume::unbounded();
    app.listen_for_updates(Box::new(CollectingReconciler {
        tx: tx2,
        reconciles: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    }));
    app.dispatch(AppAction::GetCapabilities);
    wait_for(&rx2, 20, |u| matches!(u, AppUpdate::BackendCapabilities(_)));

    app.stop_listening();
    app.dispatch(AppAction::Stop);
}
