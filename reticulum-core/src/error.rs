#[derive(Debug, PartialEq)]
pub enum RnsError {
    /// Resource-transfer specific failure with a message.
    ResourceMsg(&'static str),
    OutOfMemory,
    InvalidArgument,
    IncorrectSignature,
    IncorrectHash,
    CryptoError,
    PacketError,
    ConnectionError,
    LinkClosed,
    LinkNotReady,
    ChannelError,
    ChannelMessageTooBig,
    ChannelUnknownMessageType,
    Resource,
    Storage,
    Request,
    Iface,
    Unsupported,
}
