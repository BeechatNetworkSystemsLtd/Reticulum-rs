//! Shared-instance control channel.
//!
//! Python `multiprocessing.connection` framing (4-byte big-endian length,
//! or `-1` plus an 8-byte length) and the bidirectional authkey handshake,
//! then one msgpack payload. The digest on our challenges is SHA-256.
//! A 16-byte reply is legacy HMAC-MD5; `{sha384}` is accepted too.
//! `{sha3_256}` and `{sha3_384}` are rejected before a MAC is computed.

use std::io;

use hmac::Mac;
use rand_core::{OsRng, RngCore};
use reticulum::identity::PrivateIdentity;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CHALLENGE: &[u8] = b"#CHALLENGE#";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";
const MESSAGE_LENGTH: usize = 40;
const AUTH_MAX: usize = 256;
const HARD_MAX: usize = 32 * 1024 * 1024;

/// Where a shared-instance control listener is bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAddr {
    Tcp(u16),
    /// Linux abstract name `rns/<instance>/rpc` (without the leading NUL).
    #[cfg(target_os = "linux")]
    Abstract(String),
}

/// Authkey from a configured hex `rpc_key`, otherwise the SHA-256 of
/// `identity`'s private key bytes. With no identity, the fallback is the
/// SHA-256 of an empty input. Invalid hex logs and uses that fallback.
pub fn authkey(configured: Option<&str>, identity: Option<&PrivateIdentity>) -> Vec<u8> {
    if let Some(text) = configured {
        match decode_hex_key(text) {
            Some(key) => return key,
            None => {
                log::error!(
                    "Invalid shared instance RPC key specified, falling back to default key"
                );
            }
        }
    }
    match identity {
        Some(identity) => Sha256::digest(identity.to_bytes()).to_vec(),
        None => Sha256::digest([]).to_vec(),
    }
}

/// `None` when `text` is not hex (whitespace allowed). Empty is an empty key.
pub fn decode_hex_key(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !compact.len().is_multiple_of(2) || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    let bytes = compact.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hex = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
        out.push(u8::from_str_radix(hex, 16).ok()?);
    }
    Some(out)
}

/// Listener side: deliver a challenge, then answer the client's.
pub async fn server_handshake<S>(sock: &mut S, authkey: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    deliver_challenge(sock, authkey).await?;
    answer_challenge(sock, authkey).await
}

/// Client side: answer the listener's challenge, then deliver one.
pub async fn client_handshake<S>(sock: &mut S, authkey: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    answer_challenge(sock, authkey).await?;
    deliver_challenge(sock, authkey).await
}

pub async fn send_bytes<W>(writer: &mut W, buf: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let n = buf.len();
    if n > 0x7fff_ffff {
        let mut header = [0u8; 12];
        header[..4].copy_from_slice(&(-1i32).to_be_bytes());
        header[4..].copy_from_slice(&(n as u64).to_be_bytes());
        writer.write_all(&header).await?;
        writer.write_all(buf).await?;
    } else {
        let header = (n as i32).to_be_bytes();
        if n > 16384 {
            writer.write_all(&header).await?;
            writer.write_all(buf).await?;
        } else {
            let mut out = Vec::with_capacity(4 + n);
            out.extend_from_slice(&header);
            out.extend_from_slice(buf);
            writer.write_all(&out).await?;
        }
    }
    writer.flush().await
}

/// `Ok(None)` when `maxsize` is set and the frame is larger (the payload
/// is left unread; the caller closes).
pub async fn recv_bytes<R>(reader: &mut R, maxsize: Option<usize>) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let size_i = i32::from_be_bytes(len_buf);
    let size = if size_i == -1 {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext).await?;
        usize::try_from(u64::from_be_bytes(ext))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "length overflow"))?
    } else if size_i < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "negative message length",
        ));
    } else {
        size_i as usize
    };
    if maxsize.is_some_and(|max| size > max) {
        return Ok(None);
    }
    if size > HARD_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds 32MiB",
        ));
    }
    let mut buf = vec![0u8; size];
    if size > 0 {
        reader.read_exact(&mut buf).await?;
    }
    Ok(Some(buf))
}

/// One authenticated request. The response is the first msgpack value.
pub async fn call(
    addr: &ControlAddr,
    authkey: &[u8],
    request: &rmpv::Value,
) -> Result<rmpv::Value, String> {
    match addr {
        ControlAddr::Tcp(port) => {
            let stream = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect(("127.0.0.1", *port)),
            )
            .await
            .map_err(|_| "shared instance RPC timed out".to_string())?
            .map_err(|err| format!("shared instance RPC connect failed: {err}"))?;
            exchange(stream, authkey, request).await
        }
        #[cfg(target_os = "linux")]
        ControlAddr::Abstract(name) => {
            let stream = connect_abstract(name)?;
            exchange(stream, authkey, request).await
        }
    }
}

async fn exchange<S>(
    mut sock: S,
    authkey: &[u8],
    request: &rmpv::Value,
) -> Result<rmpv::Value, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_handshake(&mut sock, authkey)
        .await
        .map_err(|err| format!("shared instance RPC authentication failed: {err}"))?;
    let mut packed = Vec::new();
    rmpv::encode::write_value(&mut packed, request).map_err(|err| err.to_string())?;
    send_bytes(&mut sock, &packed)
        .await
        .map_err(|err| err.to_string())?;
    let frame = recv_bytes(&mut sock, None)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "rpc response too large".to_string())?;
    rmpv::decode::read_value(&mut frame.as_slice()).map_err(|err| err.to_string())
}

#[cfg(target_os = "linux")]
fn connect_abstract(name: &str) -> Result<tokio::net::UnixStream, String> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr as UnixSocketAddr;

    let socket_address = UnixSocketAddr::from_abstract_name(format!("rns/{name}/rpc").as_bytes())
        .map_err(|err| format!("shared instance RPC address: {err}"))?;
    let stream = std::os::unix::net::UnixStream::connect_addr(&socket_address)
        .map_err(|err| format!("shared instance RPC connect failed: {err}"))?;
    stream
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;
    tokio::net::UnixStream::from_std(stream).map_err(|err| err.to_string())
}

async fn deliver_challenge<S>(sock: &mut S, authkey: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut message = b"{sha256}".to_vec();
    message.extend_from_slice(&random_bytes(MESSAGE_LENGTH));
    let mut payload = CHALLENGE.to_vec();
    payload.extend_from_slice(&message);
    send_bytes(sock, &payload).await?;
    let response = recv_auth(sock).await?;
    if !verify_challenge(authkey, &message, &response) {
        let _ = send_bytes(sock, FAILURE).await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "digest received was wrong",
        ));
    }
    send_bytes(sock, WELCOME).await
}

async fn answer_challenge<S>(sock: &mut S, authkey: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let message = recv_auth(sock).await?;
    if !message.starts_with(CHALLENGE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected challenge",
        ));
    }
    let message = &message[CHALLENGE.len()..];
    if message.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "challenge too short",
        ));
    }
    let response = create_response(authkey, message)?;
    send_bytes(sock, &response).await?;
    let welcome = recv_auth(sock).await?;
    if welcome.as_slice() != WELCOME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "digest sent was rejected",
        ));
    }
    Ok(())
}

async fn recv_auth<S>(sock: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    recv_bytes(sock, Some(AUTH_MAX))
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "auth message too large"))
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Legacy frames (16 or 20 bytes) have an empty digest name.
fn digest_and_payload(message: &[u8]) -> Option<(&str, &[u8])> {
    if message.len() == 20 || message.len() == 16 {
        return Some(("", message));
    }
    if message.first() != Some(&b'{') {
        return None;
    }
    // Python searches for `}` in indices 1..10 (exclusive), clipped to the
    // message. A short `{digest}` must still parse.
    let window = message.get(1..message.len().min(10))?;
    let rel = window.iter().position(|byte| *byte == b'}')?;
    let end = 1 + rel;
    if end <= 1 {
        return None;
    }
    let name = std::str::from_utf8(message.get(1..end)?).ok()?;
    if !matches!(name, "md5" | "sha256" | "sha384") {
        return None;
    }
    Some((name, message.get(end + 1..)?))
}

fn create_response(authkey: &[u8], message: &[u8]) -> io::Result<Vec<u8>> {
    let (digest, _) = digest_and_payload(message).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unsupported challenge digest")
    })?;
    if digest.is_empty() {
        return Ok(hmac_md5(authkey, message));
    }
    let mac = compute_mac(digest, authkey, message).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unsupported challenge digest")
    })?;
    let mut out = format!("{{{digest}}}").into_bytes();
    out.extend_from_slice(&mac);
    Ok(out)
}

fn verify_challenge(authkey: &[u8], message: &[u8], response: &[u8]) -> bool {
    let Some((digest, mac_bytes)) = digest_and_payload(response) else {
        return false;
    };
    let digest = if digest.is_empty() { "md5" } else { digest };
    let Some(expected) = compute_mac(digest, authkey, message) else {
        return false;
    };
    ct_eq(&expected, mac_bytes)
}

fn compute_mac(digest: &str, key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    match digest {
        "md5" => Some(hmac_md5(key, message)),
        "sha256" => Some(hmac_sha256(key, message)),
        "sha384" => Some(hmac_sha384(key, message)),
        _ => None,
    }
}

fn hmac_md5(key: &[u8], message: &[u8]) -> Vec<u8> {
    // Legacy 20-byte challenges. SHA-2 is already in the lock; MD5 is not.
    fn md5(data: &[u8]) -> [u8; 16] {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        const K: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
            0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
            0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
            0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
            0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
            0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut buf = Vec::with_capacity(data.len() + 72);
        buf.extend_from_slice(data);
        buf.push(0x80);
        while buf.len() % 64 != 56 {
            buf.push(0);
        }
        buf.extend_from_slice(&bit_len.to_le_bytes());
        let mut state = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476];
        for chunk in buf.as_chunks::<64>().0 {
            let mut words = [0u32; 16];
            for (index, word) in words.iter_mut().enumerate() {
                let start = index * 4;
                *word = u32::from_le_bytes(chunk[start..start + 4].try_into().unwrap());
            }
            let [mut a, mut b, mut c, mut d] = state;
            for round in 0..64 {
                let (mixed, index) = match round {
                    0..=15 => ((b & c) | (!b & d), round),
                    16..=31 => ((d & b) | (!d & c), (5 * round + 1) % 16),
                    32..=47 => (b ^ c ^ d, (3 * round + 5) % 16),
                    _ => (c ^ (b | !d), (7 * round) % 16),
                };
                let mixed = mixed
                    .wrapping_add(a)
                    .wrapping_add(K[round])
                    .wrapping_add(words[index]);
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(mixed.rotate_left(S[round]));
            }
            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
        }
        let mut out = [0u8; 16];
        for (index, word) in state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&md5(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_key = [0x36u8; 64];
    let mut outer_key = [0x5cu8; 64];
    for index in 0..64 {
        inner_key[index] ^= block[index];
        outer_key[index] ^= block[index];
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&inner_key);
    inner.extend_from_slice(message);
    let inner = md5(&inner);
    let mut outer = [0u8; 80];
    outer[..64].copy_from_slice(&outer_key);
    outer[64..].copy_from_slice(&inner);
    md5(&outer).to_vec()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha384(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        hmac::Hmac::<sha2::Sha384>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::hmac_md5;

    #[test]
    fn legacy_hmac_md5_matches_rfc2104() {
        // RFC 2104 MD5 test case 1: 16-byte key of 0x0b, data "Hi There".
        let mac = hmac_md5(&[0x0b; 16], b"Hi There");
        assert_eq!(
            mac,
            [
                0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
                0xfc, 0x9d
            ]
        );
    }
}
