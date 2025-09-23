use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use reticulum::channel::{ChannelError, Message, MessageType, PackedMessage};


fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}


fn unpack_timestamp(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap()) & 0x3ffffffff
}


#[derive(Clone)]
struct TextPayload {
    text: String,
    timestamp: u64
}


impl TextPayload {
    fn new(text: String) -> Self {
        Self { text, timestamp: now() }
    }
}


impl TextPayload {
    fn pack(&self) -> Vec<u8> {
        // Packing format mimicks that of Python Reticulum, so the
        // channel example can be tested against the Channel.py example
        // in the reference implementation too.

        let mut raw = Vec::with_capacity(self.text.len() + 12);

        raw.extend_from_slice(&[0x92, 0xa3]);
        raw.extend_from_slice(self.text.as_bytes());

        raw.extend_from_slice(&[0xd7, 0xff]);
        raw.extend_from_slice(&self.timestamp.to_be_bytes());

        raw
    }

    fn unpack(raw: &[u8]) -> Result<Self, ChannelError> {
        if raw.len() <= 12 {
            return Err(ChannelError::Misc)
        }

        match String::from_utf8(raw[2..raw.len()-10].to_vec()) {
            Ok(text) => {
                let mut payload = TextPayload::new(text);
                payload.timestamp = unpack_timestamp(&raw[raw.len()-8..]);
                Ok(payload)
            },
            Err(_) => {
                Err(ChannelError::Misc)
            }
        }
    }
}


const MESSAGE_TYPE_TEXT: MessageType = 0x0101;


#[derive(Clone)]
pub enum ExampleMessage {
    Text(TextPayload)
}


impl ExampleMessage {
    pub fn new_text(text: &str) -> Self {
        Self::Text(TextPayload::new(text.to_string()))
    }
}


impl fmt::Display for ExampleMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(t) => write!(f, "Text at {}: {}", t.timestamp, t.text)
        }
    }
}


impl Message for ExampleMessage {
    fn pack(&self) -> PackedMessage {
        match self {
            Self::Text(t) => PackedMessage::new(t.pack(), MESSAGE_TYPE_TEXT)
        }
    }

    fn unpack(packed: PackedMessage) -> Result<Self, ChannelError> {
        let message_type = packed.message_type();

        match message_type {
            MESSAGE_TYPE_TEXT =>
                Ok(Self::Text(TextPayload::unpack(&packed.payload())?)),
            _ => Err(ChannelError::InvalidMessageType)
        }
    }
}
