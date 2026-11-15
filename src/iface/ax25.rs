//! AX.25 address encoding for the AX.25 KISS interface, a byte-for-byte
//! port of the frame assembly in `RNS/Interfaces/AX25KISSInterface.py`
//! (`process_outgoing` / `process_incoming`, v1.4.2).
//!
//! Outgoing data frames are prefixed with a 16-byte AX.25 UI header:
//!
//! * destination callsign `APZRNS`, SSID 0 (6 bytes, each character shifted
//!   left by one, padded with `0x20`), then `0x60 | (ssid << 1)`,
//! * source callsign/SSID from configuration, source SSID byte additionally
//!   OR-ed with `0x01` (last-address marker),
//! * UI control byte `0x03` and PID `0xF0` (no layer 3).
//!
//! Incoming frames with at most [`HEADER_SIZE`] bytes are dropped, everything
//! else is stripped of the header before being handed to the transport
//! (`process_incoming`).

use crate::error::RnsError;

/// `AX25.PID_NOLAYER3`
pub const PID_NOLAYER3: u8 = 0xF0;
/// `AX25.CTRL_UI`
pub const CTRL_UI: u8 = 0x03;
/// `AX25.HEADER_SIZE`
pub const HEADER_SIZE: usize = 16;

/// Destination callsign used by `AX25KISSInterface` (`self.dst_call`).
pub const DEFAULT_DESTINATION_CALLSIGN: &str = "APZRNS";
/// Destination SSID used by `AX25KISSInterface` (`self.dst_ssid`).
pub const DEFAULT_DESTINATION_SSID: u8 = 0;

/// Validate a source callsign/SSID pair like the Python constructor
/// (`AX25KISSInterface.__init__`): 3..=6 ASCII characters (the caller
/// upper-cases like Python's `callsign.upper().encode("ascii")`) and an
/// SSID of 0..=15.
pub fn validate_callsign(callsign: &str, ssid: u8) -> Result<(), RnsError> {
    if callsign.len() < 3 || callsign.len() > 6 {
        log::error!("invalid callsign <{callsign}>: must be 3-6 characters");
        return Err(RnsError::InvalidArgument);
    }

    if !callsign.is_ascii() {
        log::error!("invalid callsign <{callsign}>: must be ASCII");
        return Err(RnsError::InvalidArgument);
    }

    if ssid > 15 {
        log::error!("invalid ssid <{ssid}>: must be 0-15");
        return Err(RnsError::InvalidArgument);
    }

    Ok(())
}

/// Encode a callsign/SSID pair into AX.25 address bytes: 6 address bytes
/// (each character shifted left by one, padded with `0x20`) followed by the
/// encoded SSID byte.
fn encode_address(callsign: &[u8], ssid: u8, last: bool) -> [u8; 7] {
    let mut address = [0x20u8; 7];

    for (i, &byte) in callsign.iter().take(6).enumerate() {
        address[i] = byte << 1;
    }

    let mut encoded_ssid = 0x60 | (ssid << 1);
    if last {
        encoded_ssid |= 0x01;
    }
    address[6] = encoded_ssid;

    address
}

/// Pack `data` into an AX.25 UI frame (`process_outgoing`): destination
/// `APZRNS`/0, source `callsign`/`ssid`, control `CTRL_UI`, PID
/// `PID_NOLAYER3`, then the payload.
pub fn pack_ax25_frame(data: &[u8], callsign: &str, ssid: u8) -> Vec<u8> {
    pack_ax25_frame_to(
        data,
        callsign.as_bytes(),
        ssid,
        DEFAULT_DESTINATION_CALLSIGN.as_bytes(),
        DEFAULT_DESTINATION_SSID,
    )
}

/// Pack an AX.25 UI frame with explicit source and destination addresses.
#[allow(clippy::needless_range_loop)]
pub fn pack_ax25_frame_to(
    data: &[u8],
    src_call: &[u8],
    src_ssid: u8,
    dst_call: &[u8],
    dst_ssid: u8,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_SIZE + data.len());

    frame.extend_from_slice(&encode_address(dst_call, dst_ssid, false));
    frame.extend_from_slice(&encode_address(src_call, src_ssid, true));
    frame.push(CTRL_UI);
    frame.push(PID_NOLAYER3);
    frame.extend_from_slice(data);

    frame
}

/// Strip the AX.25 header from a received frame (`process_incoming`):
/// only frames longer than [`HEADER_SIZE`] carry data.
pub fn strip_ax25_header(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() > HEADER_SIZE {
        Some(&frame[HEADER_SIZE..])
    } else {
        None
    }
}

/// Decode an AX.25 address field back into a callsign string and SSID
/// (the inverse of the address encoding used by [`pack_ax25_frame`];
/// useful for diagnostics).
pub fn decode_address(address: &[u8; 7]) -> (String, u8) {
    let mut callsign = String::new();
    for &byte in address.iter().take(6) {
        let byte = byte >> 1;
        if byte != 0x10 && byte != 0x00 {
            callsign.push(byte as char);
        }
    }

    let ssid = (address[6] >> 1) & 0x0F;

    (callsign, ssid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_ax25_frame_matches_python_reference() {
        // Python AX25KISSInterface.process_outgoing with src "N0CALL"/7,
        // dst "APZRNS"/0, data de ad be ef:
        // 82a0b4a49ca6609c60868298986f03f0deadbeef
        let frame = pack_ax25_frame(&[0xde, 0xad, 0xbe, 0xef], "N0CALL", 7);
        assert_eq!(
            frame,
            vec![
                0x82, 0xa0, 0xb4, 0xa4, 0x9c, 0xa6, 0x60, 0x9c, 0x60, 0x86, 0x82, 0x98, 0x98, 0x6f,
                0x03, 0xf0, 0xde, 0xad, 0xbe, 0xef
            ]
        );
    }

    #[test]
    fn pack_ax25_frame_pads_short_callsigns() {
        // Python with src "AB1C"/0, data 01:
        // 82a0b4a49ca6608284628620206103f001
        let frame = pack_ax25_frame(&[0x01], "AB1C", 0);
        assert_eq!(
            frame,
            vec![
                0x82, 0xa0, 0xb4, 0xa4, 0x9c, 0xa6, 0x60, 0x82, 0x84, 0x62, 0x86, 0x20, 0x20, 0x61,
                0x03, 0xf0, 0x01
            ]
        );
    }

    #[test]
    fn kiss_frame_with_ax25_header_matches_python_reference() {
        // Python: kiss_frame(pack_ax25(bytes([0xde,0xad]), "N0CALL", 7))
        //       = c00082a0b4a49ca6609c60868298986f03f0deadc0
        let frame = crate::iface::kiss::encode_frame(&pack_ax25_frame(&[0xde, 0xad], "N0CALL", 7));
        assert_eq!(
            frame,
            vec![
                0xc0, 0x00, 0x82, 0xa0, 0xb4, 0xa4, 0x9c, 0xa6, 0x60, 0x9c, 0x60, 0x86, 0x82, 0x98,
                0x98, 0x6f, 0x03, 0xf0, 0xde, 0xad, 0xc0
            ]
        );
    }

    #[test]
    fn strip_header_drops_short_frames() {
        let frame = [0u8; HEADER_SIZE];
        assert!(strip_ax25_header(&frame).is_none());

        let frame = [0u8; HEADER_SIZE + 1];
        assert_eq!(strip_ax25_header(&frame), Some(&frame[HEADER_SIZE..][..1]));
    }

    #[test]
    fn callsign_validation_matches_python() {
        assert!(validate_callsign("N0CALL", 7).is_ok());
        assert!(validate_callsign("AB1C", 0).is_ok());
        assert!(validate_callsign("TOOLONGCALL", 0).is_err());
        assert!(validate_callsign("AB", 0).is_err());
        assert!(validate_callsign("N0CALL", 16).is_err());
    }

    #[test]
    fn address_round_trip() {
        let frame = pack_ax25_frame(&[1], "N0CALL", 7);
        let (dst, dst_ssid) = decode_address(frame[..7].try_into().unwrap());
        let (src, src_ssid) = decode_address(frame[7..14].try_into().unwrap());
        assert_eq!(dst, "APZRNS");
        assert_eq!(dst_ssid, 0);
        assert_eq!(src, "N0CALL");
        assert_eq!(src_ssid, 7);
    }

    #[test]
    fn announce_burst_is_not_held() {
        use crate::iface::control::{hold_announce_burst, IfaceControlState};
        use crate::iface::kiss::KissInterface;
        use crate::iface::Interface;

        // AX.25 KISS is a `KissInterface`; both modes share the override.
        assert!(!KissInterface::should_ingress_limit());

        let t0 = tokio::time::Instant::now();
        let mut generic = IfaceControlState::new(t0);
        assert!(
            hold_announce_burst(&mut generic, t0) > 0,
            "burst fixture must trip the generic limiter"
        );

        let mut state = IfaceControlState::new(t0);
        state.set_announce_ingress_limit(KissInterface::should_ingress_limit());
        assert_eq!(hold_announce_burst(&mut state, t0), 0);
    }
}
