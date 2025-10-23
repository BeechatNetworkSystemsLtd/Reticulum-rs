pub mod proto {
    tonic::include_proto!("kaonic");
}

use std::sync::Arc;
use std::time::Duration;

use proto::device_client::DeviceClient;
use proto::radio_client::RadioClient;
use proto::RadioFrame;
use reticulum_core::buffer::OutputBuffer;
use reticulum_core::codec::Serialize;
use reticulum_core::packet::Packet;
use reticulum_core::{buffer::InputBuffer, error::RnsError};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::iface::{Interface, InterfaceContext, RxMessage};

use alloc::string::String;

use super::RadioConfig;

pub const KAONIC_GRPC_URL: &str = "http://192.168.10.1:8080";

pub struct KaonicGrpc {
    addr: String,
    config: Arc<Mutex<RadioConfig>>,
    config_channel: Arc<Mutex<Option<Receiver<RadioConfig>>>>,
}

impl KaonicGrpc {
    pub fn new<T: Into<String>>(
        addr: T,
        config: RadioConfig,
        config_channel: Option<Receiver<RadioConfig>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            config: Arc::new(Mutex::new(config)),
            config_channel: Arc::new(Mutex::new(config_channel)),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let current_config = { context.inner.lock().unwrap().config.clone() };

        let iface_address = context.channel.address;

        let (rx_channel, tx_channel) = context.channel.split();

        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        let config_channel = context.inner.lock().unwrap().config_channel.clone();

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let grpc_channel = Channel::from_shared(addr.to_string())
                .unwrap()
                .connect_timeout(Duration::from_secs(30))
                .connect()
                .await;

            if let Err(err) = grpc_channel {
                log::warn!("kaonic_grpc: couldn't connect to <{}> = '{}'", addr, err);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let grpc_channel = grpc_channel.unwrap();

            let mut radio_client = RadioClient::new(grpc_channel.clone());
            let mut _device_client = DeviceClient::new(grpc_channel.clone());

            let mut recv_stream = radio_client
                .receive_stream(proto::ReceiveRequest {
                    module: 0, // Currently not used by kaonic-commd
                    timeout: 0,
                })
                .await
                .unwrap()
                .into_inner();

            log::info!("kaonic_grpc: connected to <{}>", addr);

            const BUFFER_SIZE: usize = std::mem::size_of::<Packet>() * 2;

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let rx_channel = rx_channel.clone();
                let current_config = current_config.clone();

                tokio::spawn(async move {
                    let mut rx_buffer = [0u8; BUFFER_SIZE];

                    log::trace!("kaonic_grpc: start rx task");

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            Some(result) = recv_stream.next() => {
                                if let Ok(response) = result {
                                    if let Some(frame) = response.frame {
                                        let module = current_config.lock().await.module;
                                        if frame.length > 0 && response.module == module {
                                            if let Ok(buf) = decode_frame_to_buffer(&frame, &mut rx_buffer[..]) {
                                                if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(buf)) {
                                                        let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                } else {
                                                    log::warn!("kaonic_grpc: couldn't decode packet");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    stop.cancel();
                })
            };

            if config_channel.lock().await.is_some() {
                let _config_task = {
                    let mut radio_client = radio_client.clone();
                    let cancel = cancel.clone();
                    let stop = stop.clone();
                    let config_channel = config_channel.clone();
                    let current_config = current_config.clone();

                    tokio::spawn(async move {
                        loop {
                            let mut config_channel = config_channel.lock().await;

                            tokio::select! {
                                _ = cancel.cancelled() => {
                                        break;
                                },
                                _ = stop.cancelled() => {
                                        break;
                                },
                                Some(config) = config_channel.as_mut().unwrap().recv() => {
                                    log::warn!("kaonic_grpc: change config");
                                    if let Ok(_) = radio_client.configure(config).await {
                                        let mut current_config = current_config.lock().await;
                                        *current_config = config;
                                        log::info!("kaonic_grpc: config has been changed");
                                    } else {
                                        log::error!("kaonic_grpc: config error");
                                    }
                                }
                            }
                        }
                    })
                };
            }

            let tx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let tx_channel = tx_channel.clone();
                let current_config = current_config.clone();

                tokio::spawn(async move {
                    let mut tx_buffer = [0u8; BUFFER_SIZE];
                    log::trace!("kaonic_grpc: start tx task");
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            },
                            _ = stop.cancelled() => {
                                    break;
                            },
                            Some(message) = tx_channel.recv() => {
                                let packet = message.packet;
                                let mut output = OutputBuffer::new(&mut tx_buffer);
                                if let Ok(_) = packet.serialize(&mut output) {

                                    let frame = encode_buffer_to_frame(output.as_mut_slice());

                                    let module = current_config.lock().await.module;

                                    let result = radio_client.transmit(proto::TransmitRequest{
                                        module: module,
                                        frame: Some(frame),
                                    }).await;

                                    if let Err(err) = result {
                                        log::warn!("kaonic_grpc: tx err = '{}'", err);
                                        if err.code() == tonic::Code::Unknown || err.code() == tonic::Code::Unavailable {
                                            break;
                                        }
                                    }
                                }
                            }
                        };
                    }

                    stop.cancel();
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            log::info!("kaonic_grpc: disconnected from <{}>", addr);
        }
    }
}

fn encode_buffer_to_frame(buffer: &mut [u8]) -> RadioFrame {
    // Convert the packet bytes to a list of words
    // TODO: Optimize dynamic allocation
    let words = buffer
        .chunks(4)
        .map(|chunk| {
            let mut work = 0u32;
            let chunk = chunk.iter().as_slice();

            for i in 0..chunk.len() {
                work |= (chunk[i] as u32) << (i * 8);
            }

            work
        })
        .collect::<Vec<_>>();

    proto::RadioFrame {
        data: words,
        length: buffer.len() as u32,
    }
}

fn decode_frame_to_buffer<'a>(
    frame: &RadioFrame,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], RnsError> {
    if buffer.len() < (frame.length as usize) {
        return Err(RnsError::OutOfMemory);
    }

    let length = frame.length as usize;
    let mut index = 0usize;
    for word in &frame.data {
        for i in 0..4 {
            buffer[index] = ((word >> i * 8) & 0xFF) as u8;

            index += 1;

            if index >= length {
                break;
            }
        }

        if index >= length {
            break;
        }
    }

    Ok(&buffer[..length])
}

impl Interface for KaonicGrpc {
    fn mtu() -> usize {
        2048
    }
}
