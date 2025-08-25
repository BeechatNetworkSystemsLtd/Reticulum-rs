use std::time::{SystemTime, UNIX_EPOCH};
use reticulum::channel::{Message, MessageType};


fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}


fn unpack_timestamp(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap()) & 0x3ffffffff
}


pub struct TextMessage {
    text: String,
    timestamp: u64
}


impl TextMessage {
    pub fn new(text: &str) -> Self {
        Self {
            text: text.to_string(),
            timestamp: now()
        }
    }

    fn unpack_failed(&mut self, reason: &str) {
        log::info!("Message could not be unpacked: {}", reason);
        self.text = String::new();
        self.timestamp = 0;
    }
}


impl Message for TextMessage {
    fn message_type(&self) -> Option<MessageType> {
        Some(0x0101)
    }

    fn pack(&self) -> Vec<u8> {
        // Packing format mimicks that of Python Reticulum, so the
        // channel example can be tested against the Channel.py example
        // in the reference implementation too.

        let mut raw = Vec::with_capacity(self.text.len() + 12);
        
        raw.extend_from_slice(&[0x92, 0xd7, 0xff]);
        raw.extend_from_slice(&self.timestamp.to_be_bytes());

        raw.push(0xa7);
        raw.extend_from_slice(self.text.as_bytes());
        
        raw
    }

    fn unpack(&mut self, raw: &[u8]) {
        if raw.len() <= 12 {
            self.unpack_failed("Too short");
            return;
        } 

        match String::from_utf8(raw[12..].to_vec()) {
            Ok(text) => {
                self.text = text;
                self.timestamp = unpack_timestamp(&raw[3..11]);
            },
            Err(_) => {
                self.unpack_failed("Invalid utf8");
            }
        }
    }
}

