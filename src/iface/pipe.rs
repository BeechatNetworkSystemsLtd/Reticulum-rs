//! Pipe interface, a port of `RNS/Interfaces/PipeInterface.py` (v1.4.2):
//! spawn a command and exchange HDLC-framed packets on its stdin/stdout.
//!
//! Wire format is the same simplified HDLC framing as the serial and local
//! interfaces (`0x7E` flags, `0x7D` escapes, `HW_MTU` 1064). The command is
//! split into arguments with a POSIX `shlex.split` equivalent (quotes and
//! backslash escapes). When the subprocess exits, the interface respawns it
//! after `respawn_delay` seconds (default 5).

use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use tokio::process::Command;

use crate::buffer::InputBuffer;
use crate::buffer::OutputBuffer;
use crate::iface::hdlc::Hdlc;
use crate::iface::hdlc::HdlcDecoder;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::Interface;
use super::InterfaceContext;

/// `PipeInterface.HW_MTU`
pub const HW_MTU: usize = 1064;

/// `PipeInterface` default respawn delay in seconds
pub const DEFAULT_RESPAWN_DELAY: Duration = Duration::from_secs(5);

/// Split a command line into arguments like Python's `shlex.split`
/// (POSIX mode): whitespace separation, `'...'`, `"..."` quoting and
/// backslash escapes outside single quotes.
pub fn split_command(command: &str) -> Result<Vec<String>, io::Error> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut has_token = false;

    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            has_token = true;
            continue;
        }

        match character {
            '\\' if !in_single => {
                escaped = true;
                has_token = true;
            }
            '\'' if !in_double => {
                in_single = !in_single;
                has_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_token = true;
            }
            character if character.is_whitespace() && !in_single && !in_double => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            character => {
                current.push(character);
                has_token = true;
            }
        }
    }

    if in_single || in_double || escaped {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unterminated quoting in command",
        ));
    }

    if has_token {
        args.push(current);
    }

    Ok(args)
}

/// Subprocess pipe interface (`PipeInterface`).
pub struct PipeInterface {
    command: String,
    respawn_delay: Duration,
}

impl PipeInterface {
    /// Create a pipe interface spawning `command` (default respawn delay of
    /// 5 seconds).
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            respawn_delay: DEFAULT_RESPAWN_DELAY,
        }
    }

    /// Override the respawn delay (`respawn_delay` configuration option,
    /// fractional seconds in Python).
    pub fn with_respawn_delay(mut self, delay: Duration) -> Self {
        self.respawn_delay = delay;
        self
    }

    /// Open the subprocess pipes (`open_pipe`).
    fn open_pipe(command: &str) -> Result<Child, io::Error> {
        let args = split_command(command)?;

        let (program, args) = args
            .split_first()
            .map(|(program, args)| (program.to_string(), args.to_vec()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;

        Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();

        let command = context.inner.lock().unwrap().command.clone();
        let respawn_delay = context.inner.lock().unwrap().respawn_delay;

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let mut child = match Self::open_pipe(&command) {
                Ok(child) => child,
                Err(err) => {
                    log::warn!("pipe: couldn't spawn <{}>: {}", command, err);
                    tokio::time::sleep(respawn_delay).await;
                    continue;
                }
            };

            log::info!("pipe: subprocess for <{}> connected", command);
            stats.set_online(true);

            let cancel = context.cancel.clone();
            let stop = tokio_util::sync::CancellationToken::new();

            let mut stdin = child
                .stdin
                .take()
                .expect("pipe: subprocess stdin not piped");
            let mut stdout = child
                .stdout
                .take()
                .expect("pipe: subprocess stdout not piped");

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let channel_ifac_rx = channel_ifac.clone();

                tokio::spawn(async move {
                    let mut decoder = HdlcDecoder::new(HW_MTU);
                    let mut buffer = [0u8; 4096];
                    let mut frames = Vec::new();

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            result = stdout.read(&mut buffer[..]) => match result {
                                Ok(0) => {
                                    log::debug!("pipe: subprocess terminated");
                                    stop.cancel();
                                    break;
                                }
                                Ok(n) => {
                                    frames.clear();
                                    decoder.feed(&buffer[..n], |frame| {
                                        if !frame.is_empty() {
                                            frames.push(frame.to_vec());
                                        }
                                    });

                                    for frame in frames.drain(..) {
                                        let plain = {
                                            let ifac = channel_ifac_rx
                                                .read()
                                                .expect("ifac lock")
                                                .clone();
                                            match crate::iface::ifac::decode_inbound(
                                                &frame,
                                                ifac.as_deref(),
                                                Some(&stats),
                                            ) {
                                                Some(plain) => plain,
                                                None => {
                                                    log::debug!("pipe: dropping packet with invalid access code");
                                                    continue;
                                                }
                                            }
                                        };
                                        match Packet::deserialize(
                                            &mut InputBuffer::new(&plain[..]),
                                        ) {
                                            Ok(packet) => {
                                                stats.count_rx(frame.len());
                                                let _ = rx_channel
                                                    .send(RxMessage {
                                                        address: iface_address,
                                                        packet: Box::new(packet),
                                                    })
                                                    .await;
                                            }
                                            Err(_) => log::debug!(
                                                "pipe: couldn't decode packet"
                                            ),
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::debug!("pipe: read error {}", e);
                                    stop.cancel();
                                    break;
                                }
                            }
                        }
                    }
                })
            };

            // Start transmit task
            let tx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let tx_channel = tx_channel.clone();
                let stats = stats.clone();
                let channel_ifac = channel_ifac.clone();

                tokio::spawn(async move {
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            Some(message) = tx_channel.recv() => message,
                        };

                        let packet = message.packet;
                        let mut buffer = [0u8; 2048];
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let ifac = channel_ifac.read().expect("ifac lock").clone();
                            let wire =
                                crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());
                            let frame = Hdlc::encode_frame_vec(&wire);
                            if stdin.write_all(&frame).await.is_ok() {
                                let _ = stdin.flush().await;
                                stats.count_tx(wire.len());
                            } else {
                                stop.cancel();
                                break;
                            }
                        }
                    }
                })
            };

            let child_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();

                tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = stop.cancelled() => {}
                        status = child.wait() => {
                            log::debug!("pipe: subprocess exited: {:?}", status);
                            stop.cancel();
                        }
                    }

                    let _ = child.kill().await;
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();
            child_task.await.unwrap();

            stats.set_online(false);

            // reconnect_pipe: respawn after the configured delay
            tokio::time::sleep(respawn_delay).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for PipeInterface {
    fn mtu() -> usize {
        HW_MTU
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_command_matches_shlex() {
        assert_eq!(
            split_command("/bin/cat").unwrap(),
            vec!["/bin/cat".to_string()]
        );

        assert_eq!(
            split_command("sh -c 'echo \"hello world\"'").unwrap(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo \"hello world\"".to_string(),
            ]
        );

        assert_eq!(
            split_command("tee /tmp/a\\ b.txt").unwrap(),
            vec!["tee".to_string(), "/tmp/a b.txt".to_string(),]
        );

        assert_eq!(
            split_command("script --opt=\"value with spaces\"").unwrap(),
            vec!["script".to_string(), "--opt=value with spaces".to_string(),]
        );

        assert_eq!(split_command("   ").unwrap(), Vec::<String>::new());
        assert!(split_command("sh -c 'unterminated").is_err());
    }
}
