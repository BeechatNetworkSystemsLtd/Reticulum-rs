use std::time::Duration;

use reticulum_actor::types::Action;
use reticulum_actor::types::{InterfaceConfig, NodeStatus, SharedInstanceAddress, Update};
use reticulum_actor::App;

#[test]
fn can_start_and_stop() {
    let data_dir = format!("/tmp/reticulum-actor-test-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&data_dir);
    let _ = std::fs::create_dir_all(&data_dir);

    let (app, rx) = App::new(data_dir);

    // Give the actor a moment to publish its initial state.
    std::thread::sleep(Duration::from_millis(100));
    assert!(matches!(app.state().status, NodeStatus::Stopped));

    app.dispatch(Action::Start {
        transport_enabled: false,
        identity_address: None,
    });
    let mut found_running = false;
    for _ in 0..40 {
        if let Ok(Update::FullState(s)) = rx.recv_timeout(Duration::from_millis(250)) {
            if matches!(s.status, NodeStatus::Running { .. }) {
                found_running = true;
                break;
            }
        }
    }
    assert!(found_running, "node did not reach Running state");

    app.dispatch(Action::Stop);
    let mut found_stopped = false;
    for _ in 0..20 {
        if let Ok(Update::FullState(s)) = rx.recv_timeout(Duration::from_millis(250)) {
            if matches!(s.status, NodeStatus::Stopped) {
                found_stopped = true;
                break;
            }
        }
    }
    assert!(found_stopped, "node did not return to Stopped state");
}

#[test]
fn can_add_and_remove_local_interface() {
    let data_dir = format!("/tmp/reticulum-actor-iface-test-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&data_dir);
    std::fs::create_dir_all(&data_dir).expect("create test directory");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test port");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);

    let (app, rx) = App::new(data_dir);
    app.dispatch(Action::Start {
        transport_enabled: false,
        identity_address: None,
    });
    wait_for(&rx, |u| {
        matches!(u, Update::NodeStatus(NodeStatus::Running { .. }))
    });

    app.dispatch(Action::AddInterface {
        name: "actor-test-local".into(),
        config: InterfaceConfig::LocalServer {
            address: SharedInstanceAddress::Tcp { port },
        },
        ifac: None,
        enabled: true,
    });
    let address = wait_for(
        &rx,
        |u| matches!(u, Update::InterfaceAdded { name, .. } if name == "actor-test-local"),
    );
    let Update::InterfaceAdded { address, .. } = address else {
        unreachable!()
    };

    app.dispatch(Action::RemoveInterface {
        address: address.clone(),
    });
    wait_for(
        &rx,
        |u| matches!(u, Update::InterfaceRemoved { address: removed } if removed == &address),
    );
    app.dispatch(Action::Stop);
}

fn wait_for(rx: &flume::Receiver<Update>, predicate: impl Fn(&Update) -> bool) -> Update {
    for _ in 0..80 {
        let update = rx
            .recv_timeout(Duration::from_millis(250))
            .expect("timed out waiting for actor update");
        if predicate(&update) {
            return update;
        }
    }
    panic!("matching actor update was not emitted");
}

#[test]
fn can_create_destination() {
    let data_dir = format!("/tmp/reticulum-actor-dest-test-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&data_dir);
    std::fs::create_dir_all(&data_dir).expect("create test directory");

    let (app, rx) = App::new(data_dir);
    app.dispatch(Action::Start {
        transport_enabled: false,
        identity_address: None,
    });
    wait_for(&rx, |u| {
        matches!(u, Update::NodeStatus(NodeStatus::Running { .. }))
    });

    app.dispatch(Action::CreateDestination {
        app_name: "actor-test".into(),
        aspect: "req".into(),
    });
    let destination_hash = {
        let update = wait_for(&rx, |u| {
            if let Update::FullState(s) = u {
                !s.destinations.is_empty()
            } else {
                false
            }
        });
        let Update::FullState(s) = update else {
            unreachable!()
        };
        s.destinations.first().unwrap().address_hash.clone()
    };

    let state = app.state();
    assert!(!state.destinations.is_empty());
    assert_eq!(state.destinations[0].address_hash, destination_hash);

    app.dispatch(Action::Stop);
}

// NOTE: a full loopback request/response test requires a real network
// interface pair because `OpenLink` only activates over a transport path.
// This is exercised in the broader milestone integration suite.
