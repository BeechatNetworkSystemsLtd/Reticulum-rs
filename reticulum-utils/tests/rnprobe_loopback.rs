//! rnprobe loopback round trip (Phase 8 utilities).

#[tokio::test]
async fn probe_loopback_measures_rtt() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init();

    let (destination, results) = reticulum_utils::rnprobe::run_loopback()
        .await
        .expect("probe loopback");

    assert_eq!(results.len(), 1);
    assert!(results[0].rtt.as_secs() < 5, "loopback RTT must be small");
    let rendered = reticulum_utils::rnprobe::render_results(&destination, &results);
    assert!(rendered.contains("valid proof received"), "{rendered}");
    assert!(rendered.contains(&destination.to_string()), "{rendered}");
}

#[tokio::test]
async fn probe_wait_is_honored() {
    let started = std::time::Instant::now();
    reticulum_utils::rnprobe::await_probe_gap(0, std::time::Duration::from_secs(5)).await;
    assert!(
        started.elapsed() < std::time::Duration::from_millis(50),
        "the first probe must not wait"
    );

    let started = std::time::Instant::now();
    reticulum_utils::rnprobe::await_probe_gap(1, std::time::Duration::from_millis(200)).await;
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(180),
        "inter-probe wait was not honored"
    );
}

#[test]
fn aspect_name_targets_the_probe_destination() {
    use reticulum::destination::DestinationName;
    use reticulum::identity::PrivateIdentity;

    let identity = PrivateIdentity::new_from_rand(rand_core::OsRng);
    let hash =
        DestinationName::new("rnstransport", "probe").address_hash_for(identity.as_identity());
    let resolved = reticulum_utils::rnprobe::destination_for_aspect_name(
        "rnstransport.probe",
        identity.as_identity(),
    )
    .expect("aspect name");
    assert_eq!(resolved, hash);
    assert!(
        reticulum_utils::rnprobe::destination_for_aspect_name(
            "other.service",
            identity.as_identity()
        )
        .unwrap()
            != hash
    );
    assert!(reticulum_utils::rnprobe::split_destination_name("rnstransport").is_err());
}
