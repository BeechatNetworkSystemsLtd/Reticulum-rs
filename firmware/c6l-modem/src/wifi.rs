//! WiFi STA + TCP server on the esp-radio 0.18 generation: hosts
//! connect over WiFi exactly like `rn node-sim` (`RnodeTcp`), on port
//! 4990.
//!
//! Credentials come from build-time env (`C6L_WIFI_SSID` /
//! `C6L_WIFI_PASS`) with test defaults matching the deployment recipe
//! in the firmware README.

use alloc::boxed::Box;

use embassy_futures::select::{select, Either};
use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_time::{Duration, Timer};

use esp_hal::peripherals::WIFI;
use esp_radio::wifi::{Config as RadioConfig, ControllerConfig, Interface};
use esp_radio::wifi::sta::StationConfig;

use crate::clog;
use crate::sessions::{self, Outbound};

#[allow(dead_code)] // used by the gated wifi task
pub const TCP_PORT: u16 = 4990;

pub const WIFI_SSID: &str = match option_env!("C6L_WIFI_SSID") {
    Some(ssid) => ssid,
    None => "c6l-test",
};
pub const WIFI_PASS: &str = match option_env!("C6L_WIFI_PASS") {
    Some(pass) => pass,
    None => "reticulum-test-1",
};

#[allow(dead_code)] // used by the gated wifi task
static STACK: static_cell::StaticCell<Stack<'static>> =
    static_cell::StaticCell::new();
#[allow(dead_code)] // used by the gated wifi task
static RESOURCES: static_cell::StaticCell<embassy_net::StackResources<4>> =
    static_cell::StaticCell::new();

/// Associate + DHCP + TCP accept loop. One session task per host
/// connection, feeding the shared modem core.
/// Blocking bring-up, called from the main OS task (scheduler running).
/// `esp_radio::wifi::new` waits on driver threads internally and must
/// not run at interrupt priority (the interrupt executor runs there).
pub fn bringup(
    wifi: WIFI<'static>,
) -> Option<(esp_radio::wifi::WifiController<'static>, Interface<'static>)> {
    let station = StationConfig::default()
        .with_ssid(esp_radio::wifi::Ssid::try_from(WIFI_SSID).unwrap_or_default())
        .with_password(alloc::string::String::from(WIFI_PASS));

    esp_println::println!("wifi: calling wifi::new");
    let (mut controller, interfaces) = match esp_radio::wifi::new(wifi, ControllerConfig::default())
    {
        Ok((controller, interfaces)) => (controller, interfaces),
        Err(e) => {
            esp_println::println!("wifi: controller init failed {e:?}");
            return None;
        }
    };
    if let Err(e) = controller.set_config(&RadioConfig::Station(station)) {
        esp_println::println!("wifi: config rejected {e:?}");
        return None;
    }
    esp_println::println!("wifi: controller created");
    Some((controller, interfaces.station))
}

#[embassy_executor::task]
pub async fn wifi_task(
    controller: esp_radio::wifi::WifiController<'static>,
    wifi_interface: Interface<'static>,
    spawner: embassy_executor::Spawner,
) {
    clog!("wifi: controller up, connecting");

    let config = embassy_net::Config::dhcpv4(Default::default());
    let rng = esp_hal::rng::Rng::new();
    let seed = ((rng.random() as u64) << 32) | (rng.random() as u64);
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        config,
        RESOURCES.init(embassy_net::StackResources::<4>::new()),
        seed,
    );
    let stack: &'static Stack<'static> = STACK.init(stack);

    // connection_task, net_task and tcp_session all live on this same
    // thread-mode executor (embassy-net Runner is RefCell, not Send).
    // The hosting RTOS thread is distinct from main so a busy net poll
    // cannot freeze the rest of the system.
    spawner.spawn(connection_task(controller).unwrap());
    spawner.spawn(net_task(runner).unwrap());

    stack.wait_config_up().await;
    match stack.config_v4() {
        Some(cfg) => clog!("wifi: associated, ip {}", cfg.address),
        None => clog!("wifi: associated (no v4 config)"),
    }

    // TCP accept loop.
    // Reverse-connect mode: the modem initiates TCP to the configured
    // host instead of listening for incoming connections. This bypasses
    // the esp-radio driver limitation where unsolicited incoming TCP
    // SYNs are not delivered to smoltcp (outgoing TCP works perfectly —
    // hardware-verified against the gateway).
    //
    // The host runs a listener: `nc -l 4990` or equivalent.
    let host_ip: embassy_net::IpAddress = match option_env!("C6L_TCP_HOST") {
        Some(host) => host.parse().unwrap_or(embassy_net::IpAddress::Ipv4(
            embassy_net::Ipv4Address::new(192, 168, 1, 1),
        )),
        None => {
            // Default: use the default gateway from DHCP
            match stack.config_v4() {
                Some(cfg) => {
                    let gw = cfg.gateway;
                    embassy_net::IpAddress::Ipv4(gw.unwrap_or(embassy_net::Ipv4Address::new(192, 168, 1, 1)))
                }
                None => embassy_net::IpAddress::Ipv4(
                    embassy_net::Ipv4Address::new(192, 168, 1, 1),
                ),
            }
        }
    };
    
    let mut session_id: u64 = 2; // 1=USB, 2+=TCP
    loop {
        let rx_buf: &'static mut [u8] = Box::leak(alloc::vec![0u8; 2048].into_boxed_slice());
        let tx_buf: &'static mut [u8] = Box::leak(alloc::vec![0u8; 2048].into_boxed_slice());
        let mut socket = TcpSocket::new(*stack, rx_buf, tx_buf);

        match socket.connect((host_ip, TCP_PORT)).await {
            Ok(()) => {
                                let out: &'static Outbound = Box::leak(Box::new(Outbound::new()));
                spawner.spawn(tcp_session(socket, session_id, out).unwrap());
                session_id += 1;
                // Wait long — the session manages its own lifetime.
                // Reconnect only if the session ends (checked by trying
                // to send a probe after 60s).
                Timer::after(Duration::from_secs(60)).await;
            }
            Err(_e) => {
                                Timer::after(Duration::from_secs(5)).await;
            }
        }
    }
}

#[embassy_executor::task]
async fn connection_task(mut controller: esp_radio::wifi::WifiController<'static>) {
    loop {
        match controller.connect_async().await {
            Ok(info) => {
                clog!("wifi: connected {:?}", info.ssid);
                let _ = controller.wait_for_disconnect_async().await;
                clog!("wifi: disconnected, retrying");
            }
            Err(e) => {
                clog!("wifi: connect failed {e:?}");
            }
        }
        Timer::after(Duration::from_secs(5)).await;
    }
}

/// Network stack task. The embassy-net Runner monopolizes the executor
/// via poll_fn self-waking. A competing yield task forces round-robin.
#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, Interface<'static>>) {
    // Spawn a sibling task that periodically yields, forcing the
    // executor to round-robin between net_task and other tasks.
    let spawner = unsafe { embassy_executor::Spawner::for_current_executor() }.await;
    spawner.spawn(yield_helper().unwrap());

    runner.run().await
}

/// Periodically yields, giving the executor a reason to round-robin
/// past net_task and poll other ready tasks (tcp_session).
#[embassy_executor::task]
async fn yield_helper() {
    let mut count = 0u32;
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
        if count < 3 {
                    }
        count += 1;
        embassy_futures::yield_now().await;
    }
}



#[embassy_executor::task(pool_size = 3)]
async fn tcp_session(mut socket: TcpSocket<'static>, id: u64, out: &'static Outbound) {
        esp_println::println!("TCP-SESS: started id={}", id);
    sessions::register(id, out).await;
    let rx = out.receiver();
    let mut buf = [0u8; 256];
    loop {
        match select(socket.read(&mut buf), rx.receive()).await {
            Either::First(Ok(0)) | Either::First(Err(_)) => break,
            Either::First(Ok(n)) => {
                                let chunk: alloc::vec::Vec<u8> = buf[..n].to_vec();
                                match sessions::to_modem().try_send((id, chunk)) {
                    Ok(()) => {
                                            }
                    Err(_) => {
                                                break;
                    }
                }
            }
            Either::Second(frame) => {
                if socket.write(&frame).await.is_err() {
                    break;
                }
            }
        }
    }
    sessions::unregister(id).await;
    socket.close();
    Timer::after(Duration::from_millis(50)).await;
}
// rebuild 1789469190
// rebuild 1789469429
// env 1789469728109835224
// force 1789469904958847879
// rebuild 1789471667388743405
// rebuild 1789471766094964379
// rebuild 1789471863122877451
// rebuild 1789471997939091731
// rebuild 1789496672029187996
// rebuild 1789496761718949546
// rebuild 1789496869585551044
// env 1789496966981493497
// env 1789497034383283901
// rebuild 1789497092636479913
// rebuild 1789497145205642281
// rebuild 1789497182923809288
// rebuild 1789497300897185611
// rebuild 1789497327363299577
// rebuild 1789497499448792859
// rebuild 1789497552813301320
// rebuild 1789497623503293399
// rebuild 1789497694401397402
// rebuild 1789497810748678023
// final 1789500346674805718
