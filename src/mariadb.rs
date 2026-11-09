//! A deliberately small MariaDB client: connect, authenticate, run a text query, read rows.
//!
//! Only the server metrics probe uses it, and the probe asks two read-only questions a second, so
//! a full driver (a connection pool, prepared statements, TLS, type decoding) would be dependency
//! weight bought for nothing. What is here is the classic protocol as MariaDB speaks it:
//!
//! - the v10 handshake, answered with a `HandshakeResponse41`;
//! - `mysql_native_password`, the plugin MariaDB uses for a user created `IDENTIFIED BY`, including
//!   the auth-switch request that asks for it after the fact;
//! - `COM_QUERY` with a text result set, every value returned as `Option<String>`.
//!
//! Anything else — `ed25519`, `caching_sha2_password`, TLS-only accounts — is reported as an error
//! rather than half-supported: the probe fails open, so the cost is a `-1` in three columns and a
//! warning that names the plugin.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::timeout,
};

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

/// What this client asks for. No `CLIENT_DEPRECATE_EOF`, so a result set always ends in the
/// classic EOF packet, and no `CLIENT_CONNECT_WITH_DB`: the probe reads server-wide state.
const CLIENT_CAPABILITIES: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_PROTOCOL_41
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH;

const MAX_PACKET_SIZE: u32 = 16 * 1024 * 1024;
/// `utf8mb4_general_ci`. Only identifiers and digits cross this connection, so it barely matters.
const CHARSET_UTF8MB4: u8 = 45;
const NATIVE_PASSWORD_PLUGIN: &str = "mysql_native_password";

const PACKET_OK: u8 = 0x00;
const PACKET_EOF: u8 = 0xFE;
const PACKET_ERR: u8 = 0xFF;
/// A NULL column value in a text row.
const TEXT_NULL: u8 = 0xFB;
const COM_QUERY: u8 = 0x03;

/// Where the server listens. A socket skips the TCP stack when the database shares the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MariaDbAddress {
    Tcp { host: String, port: u16 },
    Socket(String),
}

#[derive(Clone, Debug)]
pub struct MariaDbSettings {
    pub address: MariaDbAddress,
    pub user: String,
    pub password: String,
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// One authenticated connection. Not shared and not pooled: the probe owns it and replaces it
/// whenever anything goes wrong, since a half-read packet leaves the stream unusable.
pub struct MariaDbConnection {
    stream: Box<dyn Stream>,
    sequence: u8,
}

impl MariaDbConnection {
    /// Connects and authenticates, all of it inside `deadline`.
    pub async fn connect(settings: &MariaDbSettings, deadline: Duration) -> Result<Self> {
        timeout(deadline, Self::connect_inner(settings))
            .await
            .context("timed out connecting to MariaDB")?
    }

    async fn connect_inner(settings: &MariaDbSettings) -> Result<Self> {
        let stream: Box<dyn Stream> = match &settings.address {
            MariaDbAddress::Tcp { host, port } => {
                let stream = TcpStream::connect((host.as_str(), *port))
                    .await
                    .with_context(|| format!("connecting to MariaDB at {host}:{port}"))?;
                stream.set_nodelay(true).ok();
                Box::new(stream)
            }
            MariaDbAddress::Socket(path) => Box::new(
                UnixStream::connect(Path::new(path))
                    .await
                    .with_context(|| format!("connecting to MariaDB socket {path}"))?,
            ),
        };
        let mut connection = Self {
            stream,
            sequence: 0,
        };
        connection.authenticate(settings).await?;
        Ok(connection)
    }

    async fn authenticate(&mut self, settings: &MariaDbSettings) -> Result<()> {
        let greeting = self.read_packet().await?;
        if greeting.first() == Some(&PACKET_ERR) {
            bail!(
                "MariaDB refused the connection: {}",
                error_message(&greeting)
            );
        }
        let handshake = parse_handshake(&greeting)?;
        if handshake.capabilities & CLIENT_PROTOCOL_41 == 0 {
            bail!("MariaDB server does not speak protocol 4.1");
        }

        // Whatever the server proposed, the response offers native password: it is the only
        // plugin this client implements, and the server answers with an auth switch if the account
        // uses another one, which is where an unsupported plugin gets named.
        let auth_response = native_password_scramble(&settings.password, &handshake.seed);
        let response = handshake_response(&settings.user, &auth_response);
        self.write_packet(&response).await?;

        let reply = self.read_packet().await?;
        match reply.first() {
            Some(&PACKET_OK) => Ok(()),
            Some(&PACKET_ERR) => bail!("MariaDB authentication failed: {}", error_message(&reply)),
            Some(&PACKET_EOF) => {
                let (plugin, seed) = parse_auth_switch(&reply)?;
                if plugin != NATIVE_PASSWORD_PLUGIN {
                    bail!(
                        "MariaDB account uses auth plugin `{plugin}`; only {NATIVE_PASSWORD_PLUGIN} is supported"
                    );
                }
                let scramble = native_password_scramble(&settings.password, &seed);
                self.write_packet(&scramble).await?;
                let reply = self.read_packet().await?;
                match reply.first() {
                    Some(&PACKET_OK) => Ok(()),
                    Some(&PACKET_ERR) => {
                        bail!("MariaDB authentication failed: {}", error_message(&reply))
                    }
                    _ => bail!("unexpected MariaDB reply after auth switch"),
                }
            }
            _ => bail!("unexpected MariaDB reply to the handshake response"),
        }
    }

    /// Runs one text query and returns its rows, every value as text or NULL. A statement that
    /// returns no result set (an OK packet) yields no rows.
    pub async fn query(
        &mut self,
        sql: &str,
        deadline: Duration,
    ) -> Result<Vec<Vec<Option<String>>>> {
        timeout(deadline, self.query_inner(sql))
            .await
            .context("timed out waiting for a MariaDB query")?
    }

    async fn query_inner(&mut self, sql: &str) -> Result<Vec<Vec<Option<String>>>> {
        self.sequence = 0;
        let mut command = Vec::with_capacity(1 + sql.len());
        command.push(COM_QUERY);
        command.extend_from_slice(sql.as_bytes());
        self.write_packet(&command).await?;

        let first = self.read_packet().await?;
        match first.first() {
            Some(&PACKET_ERR) => bail!("MariaDB query failed: {}", error_message(&first)),
            Some(&PACKET_OK) => return Ok(Vec::new()),
            None => bail!("empty MariaDB reply"),
            _ => {}
        }
        let mut cursor = 0;
        let column_count =
            read_lenenc_int(&first, &mut cursor).context("malformed column count")? as usize;

        // Column definitions carry names and types; the probe already knows both, so they are
        // read off the wire and dropped.
        for _ in 0..column_count {
            self.read_packet().await?;
        }
        let terminator = self.read_packet().await?;
        if !is_eof(&terminator) {
            bail!("expected EOF after MariaDB column definitions");
        }

        let mut rows = Vec::new();
        loop {
            let packet = self.read_packet().await?;
            if is_eof(&packet) {
                return Ok(rows);
            }
            if packet.first() == Some(&PACKET_ERR) {
                bail!(
                    "MariaDB query failed mid-result: {}",
                    error_message(&packet)
                );
            }
            rows.push(parse_text_row(&packet, column_count)?);
        }
    }

    async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut header = [0_u8; 4];
        self.stream
            .read_exact(&mut header)
            .await
            .context("reading MariaDB packet header")?;
        let length = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
        self.sequence = header[3].wrapping_add(1);
        // A 16 MB packet would continue in the next one. Nothing the probe asks for comes close,
        // so a split packet means the stream is not what this client thinks it is.
        if length == 0xFF_FFFF {
            bail!("MariaDB packet larger than this client reads");
        }
        let mut payload = vec![0_u8; length];
        self.stream
            .read_exact(&mut payload)
            .await
            .context("reading MariaDB packet payload")?;
        Ok(payload)
    }

    async fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        let length = payload.len() as u32;
        let mut packet = Vec::with_capacity(4 + payload.len());
        packet.extend_from_slice(&length.to_le_bytes()[..3]);
        packet.push(self.sequence);
        packet.extend_from_slice(payload);
        self.sequence = self.sequence.wrapping_add(1);
        self.stream
            .write_all(&packet)
            .await
            .context("writing MariaDB packet")?;
        self.stream.flush().await.context("flushing MariaDB packet")
    }
}

struct Handshake {
    capabilities: u32,
    /// The 20-byte scramble, both halves joined and the trailing NUL dropped.
    seed: Vec<u8>,
}

fn parse_handshake(packet: &[u8]) -> Result<Handshake> {
    let mut cursor = 0;
    let protocol = *packet.first().context("empty MariaDB handshake")?;
    if protocol != 10 {
        bail!("unsupported MariaDB handshake protocol {protocol}");
    }
    cursor += 1;
    read_nul_string(packet, &mut cursor).context("handshake server version")?;
    cursor += 4; // connection id
    let mut seed = take(packet, &mut cursor, 8)
        .context("handshake scramble")?
        .to_vec();
    cursor += 1; // filler
    let lower = u16::from_le_bytes(take(packet, &mut cursor, 2)?.try_into()?) as u32;
    // A pre-4.1 server ends here. It would also fail the protocol check that follows.
    if cursor >= packet.len() {
        return Ok(Handshake {
            capabilities: lower,
            seed,
        });
    }
    cursor += 1; // charset
    cursor += 2; // status flags
    let upper = u16::from_le_bytes(take(packet, &mut cursor, 2)?.try_into()?) as u32;
    let capabilities = lower | (upper << 16);
    let auth_data_length = *take(packet, &mut cursor, 1)?.first().unwrap_or(&0) as usize;
    cursor += 10; // reserved, or MariaDB's extended capabilities
    if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let second_half = auth_data_length.saturating_sub(8).max(13);
        let rest = take(packet, &mut cursor, second_half).context("handshake scramble part 2")?;
        // The second half is NUL-terminated on the wire, and the NUL is not part of the seed.
        seed.extend_from_slice(rest.strip_suffix(&[0]).unwrap_or(rest));
    }
    Ok(Handshake { capabilities, seed })
}

fn handshake_response(user: &str, auth_response: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(64 + user.len() + auth_response.len());
    response.extend_from_slice(&CLIENT_CAPABILITIES.to_le_bytes());
    response.extend_from_slice(&MAX_PACKET_SIZE.to_le_bytes());
    response.push(CHARSET_UTF8MB4);
    response.extend_from_slice(&[0_u8; 23]);
    response.extend_from_slice(user.as_bytes());
    response.push(0);
    // CLIENT_SECURE_CONNECTION: a one-byte length, which a 20-byte scramble always fits.
    response.push(auth_response.len() as u8);
    response.extend_from_slice(auth_response);
    response.extend_from_slice(NATIVE_PASSWORD_PLUGIN.as_bytes());
    response.push(0);
    response
}

/// `[0xFE][plugin name NUL][plugin data]`.
fn parse_auth_switch(packet: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut cursor = 1;
    let plugin = read_nul_string(packet, &mut cursor).context("auth switch plugin name")?;
    let data = &packet[cursor.min(packet.len())..];
    Ok((plugin, data.strip_suffix(&[0]).unwrap_or(data).to_vec()))
}

/// `SHA1(password) XOR SHA1(seed + SHA1(SHA1(password)))`. An empty password sends nothing.
pub fn native_password_scramble(password: &str, seed: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let password_hash = Sha1::digest(password.as_bytes());
    let double_hash = Sha1::digest(password_hash);
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(double_hash);
    let mask = hasher.finalize();
    password_hash
        .iter()
        .zip(mask.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

/// An EOF packet is 0xFE with fewer than nine bytes; a longer 0xFE is a length-encoded value.
fn is_eof(packet: &[u8]) -> bool {
    packet.first() == Some(&PACKET_EOF) && packet.len() < 9
}

fn parse_text_row(packet: &[u8], column_count: usize) -> Result<Vec<Option<String>>> {
    let mut cursor = 0;
    let mut row = Vec::with_capacity(column_count);
    for _ in 0..column_count {
        if packet.get(cursor) == Some(&TEXT_NULL) {
            cursor += 1;
            row.push(None);
            continue;
        }
        let length = read_lenenc_int(packet, &mut cursor).context("malformed row value length")?;
        let bytes = take(packet, &mut cursor, length as usize).context("truncated row value")?;
        row.push(Some(String::from_utf8_lossy(bytes).into_owned()));
    }
    Ok(row)
}

fn error_message(packet: &[u8]) -> String {
    // [0xFF][code:2]['#'][sqlstate:5][message]
    let code = packet
        .get(1..3)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .unwrap_or(0);
    let message_start = if packet.get(3) == Some(&b'#') { 9 } else { 3 };
    let message = packet
        .get(message_start..)
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("({code}) {message}")
}

fn take<'a>(packet: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .context("packet offset overflow")?;
    let slice = packet
        .get(*cursor..end)
        .context("truncated MariaDB packet")?;
    *cursor = end;
    Ok(slice)
}

fn read_nul_string(packet: &[u8], cursor: &mut usize) -> Result<String> {
    let rest = packet.get(*cursor..).context("truncated MariaDB packet")?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    *cursor += (end + 1).min(rest.len());
    Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
}

fn read_lenenc_int(packet: &[u8], cursor: &mut usize) -> Result<u64> {
    let first = *take(packet, cursor, 1)?.first().unwrap_or(&0);
    let width = match first {
        0..=0xFA => return Ok(u64::from(first)),
        0xFC => 2,
        0xFD => 3,
        0xFE => 8,
        _ => bail!("invalid length-encoded integer prefix 0x{first:02X}"),
    };
    let bytes = take(packet, cursor, width)?;
    let mut value = [0_u8; 8];
    value[..width].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference vector every MySQL/MariaDB client implementation is checked against: password
    /// "root" with a known seed. Getting the XOR order or the hash nesting wrong fails here rather
    /// than as an opaque "access denied" on a server.
    #[test]
    fn native_password_matches_the_server_algorithm() {
        let seed = b"01234567890123456789";
        let scramble = native_password_scramble("root", seed);
        assert_eq!(scramble.len(), 20);
        // Verify the defining property instead of a magic constant: the server keeps
        // SHA1(SHA1(password)) and checks SHA1(scramble XOR SHA1(seed + stored)) == stored.
        let stored = Sha1::digest(Sha1::digest(b"root"));
        let mut hasher = Sha1::new();
        hasher.update(seed);
        hasher.update(stored);
        let mask = hasher.finalize();
        let recovered: Vec<u8> = scramble
            .iter()
            .zip(mask.iter())
            .map(|(left, right)| left ^ right)
            .collect();
        assert_eq!(Sha1::digest(&recovered), stored);

        assert!(native_password_scramble("", seed).is_empty());
    }

    #[test]
    fn a_mariadb_handshake_yields_the_whole_seed() {
        let mut packet = vec![10];
        packet.extend_from_slice(b"11.4.5-MariaDB\0");
        packet.extend_from_slice(&7_u32.to_le_bytes());
        packet.extend_from_slice(b"abcdefgh");
        packet.push(0);
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        packet.extend_from_slice(&(capabilities as u16).to_le_bytes());
        packet.push(45);
        packet.extend_from_slice(&2_u16.to_le_bytes());
        packet.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
        packet.push(21);
        packet.extend_from_slice(&[0; 10]);
        packet.extend_from_slice(b"ijklmnopqrst\0");
        packet.extend_from_slice(b"mysql_native_password\0");

        let handshake = parse_handshake(&packet).unwrap();
        assert_eq!(handshake.seed, b"abcdefghijklmnopqrst");
        assert_eq!(handshake.capabilities, capabilities);
    }

    #[test]
    fn text_rows_decode_values_and_nulls() {
        let mut packet = vec![3];
        packet.extend_from_slice(b"123");
        packet.push(TEXT_NULL);
        packet.push(0);
        let row = parse_text_row(&packet, 3).unwrap();
        assert_eq!(row, vec![Some("123".into()), None, Some(String::new())]);
        assert!(parse_text_row(&[5, b'1'], 1).is_err());
    }

    #[test]
    fn length_encoded_integers_cover_every_width() {
        let mut cursor = 0;
        assert_eq!(read_lenenc_int(&[0xFA], &mut cursor).unwrap(), 250);
        cursor = 0;
        assert_eq!(
            read_lenenc_int(&[0xFC, 0x34, 0x12], &mut cursor).unwrap(),
            0x1234
        );
        cursor = 0;
        assert_eq!(
            read_lenenc_int(&[0xFD, 0x56, 0x34, 0x12], &mut cursor).unwrap(),
            0x12_3456
        );
        cursor = 0;
        assert_eq!(
            read_lenenc_int(&[0xFE, 1, 0, 0, 0, 0, 0, 0, 0], &mut cursor).unwrap(),
            1
        );
        cursor = 0;
        assert!(read_lenenc_int(&[0xFB], &mut cursor).is_err());
    }

    #[test]
    fn eof_is_told_apart_from_a_long_value() {
        assert!(is_eof(&[0xFE, 0, 0, 2, 0]));
        assert!(!is_eof(&[0xFE, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_eof(&[0x00]));
    }

    #[test]
    fn error_packets_keep_code_and_message() {
        let mut packet = vec![0xFF, 0x15, 0x04, b'#'];
        packet.extend_from_slice(b"28000Access denied");
        assert_eq!(error_message(&packet), "(1045) Access denied");
    }
}
