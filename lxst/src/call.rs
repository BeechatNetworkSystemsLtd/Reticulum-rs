//! The LXST call endpoint (Python `LXST/Call.py`).
//!
//! Announces an `lxst.call.endpoint` single destination and manages a call:
//!
//! * [`CallEndpoint::announce`] announces the destination
//! * incoming links surface as [`CallEvent::IncomingCall`] through
//!   [`CallEndpoint::events`]
//! * [`CallEndpoint::answer`] builds the receive and transmit paths for the
//!   link with a chosen codec
//! * [`CallEndpoint::terminate`] stops both paths and tears the link down
//!
//! The receive/transmit structure mirrors the Python `answer()`:
//!
//! ```text
//! receive : LinkSource -> decode -> events / sink
//! transmit: frames -> Packetizer -> link data packets
//! ```
//!
//! The much larger `Primitives/Telephony.py::Telephone` state machine (ring
//! timeouts, dial/busy tones, ringtones, profile switching, allow/block
//! lists, auto-answer) is **not** ported since it depends on OS audio
//! hardware; the signalling codes it defines live in
//! [`crate::network::Signal`].

use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};

use reticulum::destination::link::{Link, LinkEvent, LinkEventData, LinkId};
use reticulum::destination::{
    DestinationDesc, DestinationName, SingleInputDestination, SingleOutputDestination,
};
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{Transport, TransportConfig};

use crate::codecs::{new_codec, CodecType};
use crate::common::AudioFrame;
use crate::network::{LinkSource, LinkSourceEvent, Packetizer, Signal};
use crate::{LxstError, APP_NAME};

/// Destination aspects of the call endpoint (Python:
/// `RNS.Destination(identity, IN, SINGLE, APP_NAME, "call", "endpoint")`).
pub const CALL_ASPECTS: [&str; 2] = ["call", "endpoint"];

/// Build the call endpoint destination name (`lxst.call.endpoint`).
pub fn call_endpoint_name() -> DestinationName {
    DestinationName::new(APP_NAME, &CALL_ASPECTS.join("."))
}

/// Destination name of the telephony primitive (Python:
/// `RNS.Destination(..., APP_NAME, "telephony")`); provided for
/// interoperability even though the `Telephone` primitive itself is not
/// ported.
pub fn telephony_name() -> DestinationName {
    DestinationName::new(APP_NAME, "telephony")
}

/// Events emitted by a [`CallEndpoint`].
#[derive(Debug)]
pub enum CallEvent {
    /// A link was established to our call endpoint: an incoming call.
    IncomingCall(LinkId),
    /// Signalling arrived on the given link.
    Signalling(LinkId, Vec<u8>),
    /// A decoded frame arrived on the given link.
    Frame(LinkId, AudioFrame),
    /// The given link was closed.
    Closed(LinkId),
}

/// A remote LXST call endpoint we can send to (built from the remote
/// identity, Python: `RNS.Destination(identity, OUT, SINGLE, APP_NAME,
/// "call", "endpoint")`).
#[derive(Clone)]
pub struct RemoteCallDestination {
    pub desc: DestinationDesc,
}

impl RemoteCallDestination {
    pub fn for_identity(identity: &PrivateIdentity) -> Self {
        let name = call_endpoint_name();
        let dest = SingleOutputDestination::new(*identity.as_identity(), name);
        Self { desc: dest.desc }
    }

    /// Send a payload toward this destination over all active out-links that
    /// target it.
    pub async fn send(&self, transport: &Transport, payload: &[u8]) {
        transport
            .send_to_out_links(&self.desc.address_hash, payload)
            .await;
    }
}

/// A call in progress: receive events plus a transmit queue.
pub struct ActiveCall {
    pub link_id: LinkId,
    /// Receive-side events (decoded frames, signalling, codec switches).
    pub received: mpsc::Receiver<LinkSourceEvent>,
    /// Transmit queue for encoded frames.
    pub transmit: mpsc::Sender<Vec<u8>>,
    packetizer: Packetizer,
    link_source: Arc<Mutex<LinkSource>>,
}

impl ActiveCall {
    /// Codec currently used on the transmit path.
    pub fn codec(&self) -> CodecType {
        self.packetizer.codec()
    }

    /// Encode `frame` with the call codec and send it (convenience for
    /// callers that do not run a pipeline).
    pub async fn send_frame(&self, frame: &[u8]) -> Result<(), LxstError> {
        self.packetizer.send_frame(frame).await
    }

    /// Send a signalling code to the remote.
    pub async fn signal(&self, signal: Signal) -> Result<(), LxstError> {
        self.packetizer.send_signal(signal.code()).await
    }

    /// Queue an encoded frame for transmission (used by pipelines).
    pub async fn queue_frame(&self, frame: Vec<u8>) -> Result<(), LxstError> {
        self.transmit
            .send(frame)
            .await
            .map_err(|_| LxstError::InvalidState("transmit channel closed".into()))
    }

    /// The receive-side codec holder (allows inspecting / switching codecs).
    pub fn link_source(&self) -> Arc<Mutex<LinkSource>> {
        self.link_source.clone()
    }
}

/// The call endpoint (Python `LXST.Call.CallEndpoint`).
pub struct CallEndpoint {
    identity: PrivateIdentity,
    destination: Arc<Mutex<SingleInputDestination>>,
    transport: Arc<Transport>,
    events: mpsc::Sender<CallEvent>,
    active_call: Option<ActiveCall>,
}

impl CallEndpoint {
    /// Create the endpoint, register its `lxst.call.endpoint` destination on
    /// the transport and start watching link events.
    /// Create the endpoint, registering its `lxst.call.endpoint` destination
    /// on the transport, and start watching link events.
    ///
    /// Requires sole ownership of `transport` (the destination registration
    /// API is `&mut self`). Use [`CallEndpoint::with_destination`] when the
    /// transport is already shared.
    pub async fn new(
        mut transport: Arc<Transport>,
        identity: PrivateIdentity,
    ) -> Result<(Self, mpsc::Receiver<CallEvent>), LxstError> {
        let destination = match Arc::get_mut(&mut transport) {
            Some(t) => {
                t.add_destination(identity.clone(), call_endpoint_name())
                    .await
            }
            None => {
                return Err(LxstError::InvalidState(
                    "CallEndpoint::new requires sole ownership of the transport; \
                     use with_destination() for an already-shared transport"
                        .into(),
                ))
            }
        };
        Ok(Self::with_destination(transport, destination, identity))
    }

    /// Create the endpoint around an already-registered call destination.
    pub fn with_destination(
        transport: Arc<Transport>,
        destination: Arc<Mutex<SingleInputDestination>>,
        identity: PrivateIdentity,
    ) -> (Self, mpsc::Receiver<CallEvent>) {
        let (tx, rx) = mpsc::channel(64);
        let endpoint = Self {
            identity,
            destination,
            transport,
            events: tx.clone(),
            active_call: None,
        };
        endpoint.spawn_link_watcher(tx);
        (endpoint, rx)
    }

    /// Announce the call endpoint (Python `announce`).
    pub async fn announce(&self) {
        self.transport.send_announce(&self.destination, None).await;
    }

    /// Identity of this endpoint.
    pub fn identity(&self) -> &PrivateIdentity {
        &self.identity
    }

    /// Address hash of the call destination.
    pub async fn address_hash(&self) -> reticulum::hash::AddressHash {
        self.destination.lock().await.desc.address_hash
    }

    /// Destination of this endpoint.
    pub fn destination(&self) -> Arc<Mutex<SingleInputDestination>> {
        self.destination.clone()
    }

    /// Transport the endpoint is bound to.
    pub fn transport(&self) -> Arc<Transport> {
        self.transport.clone()
    }

    /// Whether a call is currently active.
    pub fn has_active_call(&self) -> bool {
        self.active_call.is_some()
    }

    /// Answer an incoming call on `link` (Python `answer`).
    ///
    /// Builds the receive path (a [`LinkSource`] decoding incoming frames
    /// with `codec_type`) and the transmit path (a [`Packetizer`] framing
    /// encoded frames onto the link). Returns a clone-able handle plus takes
    /// ownership of the receive stream.
    pub async fn answer(
        &mut self,
        link: Arc<Mutex<Link>>,
        codec_type: CodecType,
        sink_samplerate: Option<u32>,
        sink_channels: Option<usize>,
    ) -> Result<ActiveCallHandle, LxstError> {
        let codec = new_codec(codec_type).map_err(|_| LxstError::UnsupportedCodec(codec_type))?;
        let (link_source, mut source_events) = LinkSource::with_codec_instance(Some(codec));
        let mut link_source = link_source;
        link_source.set_sink_params(sink_samplerate, sink_channels);
        let link_source = Arc::new(Mutex::new(link_source));

        let link_id = *link.lock().await.id();
        let (packetizer, mut transmit_rx) =
            Packetizer::new_for_link(self.transport.clone(), link.clone(), codec_type);

        // Bridge reticulum link events into the LinkSource and drive the
        // packetizer from the transmit queue.
        let mut link_events = self.transport.events_for_link(link_id).await;
        let events_tx = self.events.clone();
        let source = link_source.clone();
        let packetizer_task = packetizer.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = link_events.recv() => {
                        match event {
                            Ok(LinkEventData { id, event, .. }) if id == link_id => match event {
                                LinkEvent::Data(payload) => {
                                    source.lock().await.handle_packet(payload.as_slice()).await;
                                }
                                LinkEvent::Closed => {
                                    let _ = events_tx.send(CallEvent::Closed(id)).await;
                                    break;
                                }
                                _ => {}
                            },
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                    frame = transmit_rx.recv() => {
                        if let Some(frame) = frame {
                            if let Err(e) = packetizer_task.send_frame(&frame).await {
                                log::warn!("call: transmit failed: {e}");
                            }
                        }
                    }
                    // the select is biased toward link events; frames are
                    // drained as they arrive
                }
            }
        });

        // Fan decoded frames and signalling out to the endpoint events and
        // the ActiveCall receiver.
        let (received_tx, received_rx) = mpsc::channel(256);
        let events_tx = self.events.clone();
        tokio::spawn(async move {
            while let Some(event) = source_events.recv().await {
                match event {
                    LinkSourceEvent::Frame(frame) => {
                        let _ = events_tx
                            .send(CallEvent::Frame(link_id, frame.clone()))
                            .await;
                        let _ = received_tx.send(LinkSourceEvent::Frame(frame)).await;
                    }
                    LinkSourceEvent::Signals(signals) => {
                        let _ = events_tx
                            .send(CallEvent::Signalling(link_id, signals.clone()))
                            .await;
                        let _ = received_tx.send(LinkSourceEvent::Signals(signals)).await;
                    }
                    other => {
                        let _ = received_tx.send(other).await;
                    }
                }
            }
        });

        let handle = ActiveCallHandle {
            link_id,
            transmit: packetizer.frames(),
            codec_type,
        };

        self.active_call = Some(ActiveCall {
            link_id,
            received: received_rx,
            transmit: packetizer.frames(),
            packetizer,
            link_source,
        });

        Ok(handle)
    }

    /// Take the active call, if any (Python keeps
    /// `receive_pipeline`/`transmit_pipeline` as attributes).
    pub fn take_active_call(&mut self) -> Option<ActiveCall> {
        self.active_call.take()
    }

    /// Terminate the active call (Python `terminate`): closes the transmit
    /// path and tears the link down.
    pub async fn terminate(&mut self) -> Result<(), LxstError> {
        if let Some(call) = self.active_call.take() {
            let link_id = call.link_id;
            // dropping the ActiveCall closes the transmit path
            drop(call);
            self.transport.link_close(link_id).await?;
        }
        Ok(())
    }

    fn spawn_link_watcher(&self, events: mpsc::Sender<CallEvent>) {
        let transport = self.transport.clone();
        let destination = self.destination.clone();
        tokio::spawn(async move {
            let mut link_events = transport.in_link_events();
            while let Ok(LinkEventData {
                id,
                address_hash,
                event,
            }) = link_events.recv().await
            {
                let destination_hash = destination.lock().await.desc.address_hash;
                if address_hash != destination_hash {
                    continue;
                }
                match event {
                    LinkEvent::Activated => {
                        let _ = events.send(CallEvent::IncomingCall(id)).await;
                    }
                    LinkEvent::Closed => {
                        let _ = events.send(CallEvent::Closed(id)).await;
                    }
                    _ => {}
                }
            }
        });
    }
}

/// Clone-able handle to an answered call, for handing to pipelines.
pub struct ActiveCallHandle {
    pub link_id: LinkId,
    transmit: mpsc::Sender<Vec<u8>>,
    codec_type: CodecType,
}

impl ActiveCallHandle {
    /// Encoded-frame sender for the transmit pipeline.
    pub fn transmit(&self) -> mpsc::Sender<Vec<u8>> {
        self.transmit.clone()
    }

    pub fn codec_type(&self) -> CodecType {
        self.codec_type
    }
}

/// Utility for constructing a transport bound to a call identity (Python
/// builds `RNS.Transport` in the application).
pub fn call_transport(identity: &PrivateIdentity, name: &str) -> Arc<Transport> {
    Arc::new(Transport::new(TransportConfig::new(name, identity)))
}

//***************************************************************************//
// tests
//***************************************************************************//

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use reticulum::destination::link::LinkStatus;

    async fn endpoint_named(
        name: &str,
    ) -> (Arc<Transport>, CallEndpoint, mpsc::Receiver<CallEvent>) {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let transport = call_transport(&identity, name);
        let (endpoint, events) = CallEndpoint::new(transport, identity).await.unwrap();
        (endpoint.transport(), endpoint, events)
    }

    #[tokio::test]
    async fn endpoint_registers_call_destination() {
        let (transport, endpoint, _events) = endpoint_named("callee").await;
        let identity = endpoint.identity().clone();

        let hash = endpoint.address_hash().await;
        // destination is registered with the transport
        assert!(transport.has_destination(&hash).await);

        // the name hash matches lxst.call.endpoint
        let name = call_endpoint_name();
        let expected = {
            let dest = SingleInputDestination::new(identity.clone(), name);
            dest.desc.address_hash
        };
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn remote_destination_hash_matches_local() {
        // The remote view of our destination must hash to the same address,
        // otherwise calls could never be routed.
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let transport = call_transport(&identity, "local");
        let (endpoint, _events) = CallEndpoint::new(transport, identity.clone())
            .await
            .unwrap();
        let local_hash = endpoint.address_hash().await;

        let remote = RemoteCallDestination::for_identity(&identity);
        assert_eq!(local_hash, remote.desc.address_hash);
    }

    #[tokio::test]
    async fn terminate_without_call_is_noop() {
        let (_transport, mut endpoint, _events) = endpoint_named("x").await;
        assert!(endpoint.terminate().await.is_ok());
        assert!(!endpoint.has_active_call());
    }

    #[tokio::test]
    async fn unsupported_codec_fails_answer() {
        // Build a fake link by hand (no network needed) with a codec that is
        // compiled out of the default build.
        let (_transport, mut endpoint, _events) = endpoint_named("x").await;

        let dest = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            call_endpoint_name(),
        )
        .desc;
        let link = Arc::new(Mutex::new(Link::new(dest)));
        link.lock().await.set_status(LinkStatus::Active);

        #[cfg(feature = "opus")]
        let unsupported = CodecType::Codec2;
        #[cfg(all(not(feature = "opus"), not(feature = "codec2")))]
        let unsupported = CodecType::Opus;
        #[cfg(all(not(feature = "opus"), feature = "codec2"))]
        let unsupported = CodecType::Opus;

        let result = endpoint.answer(link, unsupported, None, None).await;
        assert!(matches!(result, Err(LxstError::UnsupportedCodec(_))));
    }

    #[tokio::test]
    async fn answer_builds_active_call() {
        let (_transport, mut endpoint, _events) = endpoint_named("x").await;

        let dest = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            call_endpoint_name(),
        )
        .desc;
        let link = Arc::new(Mutex::new(Link::new(dest)));
        link.lock().await.set_status(LinkStatus::Active);

        let handle = endpoint
            .answer(link, CodecType::Raw, Some(48_000), Some(1))
            .await
            .unwrap();
        assert_eq!(handle.codec_type(), CodecType::Raw);
        assert!(endpoint.has_active_call());

        let call = endpoint.take_active_call().unwrap();
        assert_eq!(call.codec(), CodecType::Raw);
        // transmit path accepts frames
        call.transmit.send(vec![0x40, 1, 2]).await.unwrap();
    }
}
