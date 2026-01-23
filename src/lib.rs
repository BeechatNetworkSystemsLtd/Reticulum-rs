#[cfg(feature = "alloc")]
extern crate alloc;

pub mod buffer;
pub mod crypt;
pub mod destination;
pub mod error;
pub mod hash;
pub mod identity;
pub mod iface;
pub mod packet;
pub mod transport;

pub use crate::destination::{group_decrypt, group_encrypt};
pub use crate::hash::lxmf_address_hash;
pub use crate::identity::{lxmf_sign, lxmf_verify};
pub use crate::packet::{LXMF_MAX_PAYLOAD, Packet};
pub use crate::transport::{DeliveryReceipt, ReceiptHandler};

mod utils;
mod serde;
