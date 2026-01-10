#[derive(Debug)]
pub enum RnsError {
    OutOfMemory,
    InvalidArgument,
    IncorrectSignature,
    IncorrectHash,
    CryptoError,
    PacketError,
    ConnectionError,
}

impl std::fmt::Display for RnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}