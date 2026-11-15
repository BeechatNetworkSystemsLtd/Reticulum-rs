use std::time::Duration;

use flume::Sender;
use reticulum_ffi::{AppAction, AppReconciler, AppUpdate, FfiApp, InterfaceConfig};

struct TestReconciler(Sender<AppUpdate>);

impl AppReconciler for TestReconciler {
    fn reconcile(&self, update: AppUpdate) {
        let _ = self.0.send(update);
    }
}

#[test]
fn can_start_and_stop() {
    let data_dir = format!("/tmp/reticulum-ffi-test-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&data_dir);
    let _ = std::fs::create_dir_all(&data_dir);

    let app = FfiApp::new(data_dir);

    // Give the actor a moment to publish its initial state.
    std::thread::sleep(Duration::from_millis(100));
    assert!(matches!(
        app.state().status,
        reticulum_ffi::NodeStatus::Stopped
    ));

    let (tx, rx) = flume::unbounded();
    let reconciler = TestReconciler(tx);
    app.listen_for_updates(Box::new(reconciler));

    app.dispatch(AppAction::Start {
        transport_enabled: false,
        identity_address: None,
    });

    app.dispatch(AppAction::AddInterface {
        name: "test-tcp".into(),
        config: InterfaceConfig::TcpClient {
            address: "127.0.0.1:0".into(),
        },
        ifac: None,
        enabled: true,
    });

    // Give the actor a moment to reflect the added interface in state.
    std::thread::sleep(Duration::from_millis(100));

    if let Some(iface) = app.state().interfaces.first() {
        app.dispatch(AppAction::RemoveInterface {
            address: iface.address.clone(),
        });
    }

    let mut found_running = false;
    for _ in 0..40 {
        if let Ok(AppUpdate::FullState(s)) = rx.recv_timeout(Duration::from_millis(250)) {
            if matches!(s.status, reticulum_ffi::NodeStatus::Running { .. }) {
                found_running = true;
                break;
            }
        }
    }
    assert!(found_running, "node did not reach Running state");

    app.dispatch(AppAction::Stop);
    let mut found_stopped = false;
    for _ in 0..20 {
        if let Ok(AppUpdate::FullState(s)) = rx.recv_timeout(Duration::from_millis(250)) {
            if matches!(s.status, reticulum_ffi::NodeStatus::Stopped) {
                found_stopped = true;
                break;
            }
        }
    }
    assert!(found_stopped, "node did not return to Stopped state");
}
