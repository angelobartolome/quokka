//! Pure packet parsers: IP / TCP / UDP / ICMP summary, DNS queries, TLS SNI.
//!
//! Lifted out of `mod.rs` so each parser can be tested with hand-crafted
//! fixtures without touching the device layer. Every function here is
//! pure: input is bytes, output is `Option<...>`.

use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::device::Packet;

/// Offsets we try, in order, to locate the IP header inside `Packet::data`.
///
/// The idevice crate's `normalize_data()` only prepends the 14-byte
/// synthetic Ethernet header when `frame_pre_length == 0`, and only
/// strips the 4-byte BSD loopback prefix for `pdp_ip*` interfaces.
/// Anything else (notably `utun*`, used by RemotePairing on iOS 17+)
/// arrives raw — Ethernet not added, BSD loopback prefix not stripped.
/// We don't have `frame_pre_length` at this layer, so we attempt parses
/// at each plausible offset and accept the first one that succeeds.
///
/// Order matters for ambiguous payloads: 14 wins for the common case
/// (en0, pdp_ip0 after normalization), then 4 for utun BSD-loopback
/// framing, then 0 for raw IP as a last-resort.
const IP_OFFSET_CANDIDATES: &[usize] = &[14, 4, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound, written from the device.
    Out,
    /// Inbound, received by the device.
    In,
}

impl Direction {
    /// Map the raw pcapd `io` byte. The upstream crate doesn't document the
    /// semantics; we follow the convention used by macOS BPF (`PKTAP_FLAG_
    /// DIR_OUT`-style) where `1` is outbound. **Validate empirically** with
    /// known traffic and flip this if needed — the test suite locks in
    /// whichever direction we commit to.
    pub fn from_io_byte(io: u8) -> Self {
        if io == 1 {
            Direction::Out
        } else {
            Direction::In
        }
    }

    pub(super) fn arrow(self) -> &'static str {
        match self {
            Direction::Out => "↑",
            Direction::In => "↓",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl Protocol {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Other => "OTHER",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub ip: IpAddr,
    /// `None` for ICMP / "Other" — those have no L4 port concept here.
    pub port: Option<u16>,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // IPv6 needs brackets to disambiguate the colon-separated port.
        match (self.ip, self.port) {
            (IpAddr::V6(v6), Some(p)) => write!(f, "[{v6}]:{p}"),
            (IpAddr::V6(v6), None) => write!(f, "[{v6}]"),
            (IpAddr::V4(v4), Some(p)) => write!(f, "{v4}:{p}"),
            (IpAddr::V4(v4), None) => write!(f, "{v4}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub protocol: Protocol,
    pub src: Endpoint,
    pub dst: Endpoint,
}

/// Pure parsing function. Skips the synthetic 14-byte Ethernet header the
/// idevice crate prepended, then lets etherparse decide IPv4 vs IPv6 by
/// peeking at the IP version nibble. Returns `None` on any parse failure
/// (truncated payload, unknown protocol, malformed header) — the caller
/// is expected to fall back to a `<parse error>` line rather than crash.
pub fn parse_summary(packet: &Packet) -> Option<ParsedPacket> {
    let parsed = IP_OFFSET_CANDIDATES
        .iter()
        .filter(|&&off| packet.data.len() > off)
        .find_map(|&off| SlicedPacket::from_ip(&packet.data[off..]).ok())?;

    let (src_ip, dst_ip) = match parsed.net.as_ref()? {
        NetSlice::Ipv4(s) => (
            IpAddr::V4(s.header().source_addr()),
            IpAddr::V4(s.header().destination_addr()),
        ),
        NetSlice::Ipv6(s) => (
            IpAddr::V6(s.header().source_addr()),
            IpAddr::V6(s.header().destination_addr()),
        ),
        // etherparse may add new NetSlice variants (e.g. ARP); treat them
        // as unparseable rather than guessing.
        _ => return None,
    };

    let (protocol, src_port, dst_port) = match parsed.transport.as_ref() {
        Some(TransportSlice::Tcp(t)) => (
            Protocol::Tcp,
            Some(t.source_port()),
            Some(t.destination_port()),
        ),
        Some(TransportSlice::Udp(u)) => (
            Protocol::Udp,
            Some(u.source_port()),
            Some(u.destination_port()),
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
            (Protocol::Icmp, None, None)
        }
        // Unknown transport (or none) — still useful to log src/dst IP.
        _ => (Protocol::Other, None, None),
    };

    Some(ParsedPacket {
        protocol,
        src: Endpoint {
            ip: src_ip,
            port: src_port,
        },
        dst: Endpoint {
            ip: dst_ip,
            port: dst_port,
        },
    })
}

/// Walk the same offset candidates as [`parse_summary`], stopping at the
/// first slice that decodes as UDP, and return the L7 payload.
pub(super) fn try_extract_udp_payload(p: &Packet) -> Option<&[u8]> {
    for &off in IP_OFFSET_CANDIDATES {
        let slice = p.data.get(off..)?;
        if let Ok(parsed) = SlicedPacket::from_ip(slice) {
            if let Some(TransportSlice::Udp(udp)) = parsed.transport {
                return Some(udp.payload());
            }
        }
    }
    None
}

/// Same shape as [`try_extract_udp_payload`] but for TCP. Returns the
/// segment payload (post-options), which is what TLS ClientHello sits in.
pub(super) fn try_extract_tcp_payload(p: &Packet) -> Option<&[u8]> {
    for &off in IP_OFFSET_CANDIDATES {
        let slice = p.data.get(off..)?;
        if let Ok(parsed) = SlicedPacket::from_ip(slice) {
            if let Some(TransportSlice::Tcp(tcp)) = parsed.transport {
                return Some(tcp.payload());
            }
        }
    }
    None
}

/// One parsed DNS query — only the bits the `--dns` renderer needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Record type as a string (`"A"`, `"AAAA"`, `"PTR"`, ...). Unknown
    /// codes render as `"TYPE<n>"` so we don't drop the line silently.
    pub qtype: String,
    /// Fully-qualified-ish name, dot-joined from the wire labels.
    pub qname: String,
}

/// Parse a UDP payload as a DNS *query* message. Returns `None` for
/// responses, malformed packets, or anything that doesn't look like DNS.
pub fn parse_dns_query(payload: &[u8]) -> Option<DnsQuery> {
    // RFC 1035 §4.1.1 — fixed 12-byte header.
    if payload.len() < 12 {
        return None;
    }
    // Flags: QR bit is the top bit of byte 2. We only want queries (0).
    let qr_is_response = payload[2] & 0x80 != 0;
    if qr_is_response {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12usize;
    let qname = read_dns_name(payload, &mut idx, 0)?;
    if idx + 4 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
    Some(DnsQuery {
        qtype: dns_qtype_name(qtype),
        qname,
    })
}

/// Walk a DNS name with bounded compression-pointer recursion. The depth
/// guard keeps a malicious or buggy packet from looping forever via
/// pointers that reference each other.
fn read_dns_name(buf: &[u8], idx: &mut usize, depth: u8) -> Option<String> {
    if depth > 5 {
        return None;
    }
    let mut labels: Vec<String> = Vec::new();
    loop {
        if *idx >= buf.len() {
            return None;
        }
        let len = buf[*idx];
        if len == 0 {
            *idx += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Pointer: two bottom bits of `len` + next byte = absolute
            // offset within the message. Pointers don't usually appear in
            // queries, but we handle them defensively.
            if *idx + 1 >= buf.len() {
                return None;
            }
            let offset = (((len & 0x3F) as usize) << 8) | (buf[*idx + 1] as usize);
            *idx += 2;
            let mut sub = offset;
            let tail = read_dns_name(buf, &mut sub, depth + 1)?;
            labels.push(tail);
            break;
        }
        let len = len as usize;
        *idx += 1;
        if *idx + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[*idx..*idx + len]).ok()?;
        labels.push(label.to_string());
        *idx += len;
    }
    Some(labels.join("."))
}

fn dns_qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        257 => "CAA".into(),
        other => format!("TYPE{other}"),
    }
}

/// Extract SNI hostname from a TCP payload that starts with a TLS record.
/// Returns `None` for non-TLS payloads, non-ClientHello records, or any
/// truncation that prevents reading the SNI extension.
///
/// Hand-rolled instead of pulling in `tls-parser` (heavy, parses things
/// we don't need). RFC 8446 §4.1.2 + RFC 6066 §3 cover the format.
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    // TLS record: ContentType(1) ProtocolVersion(2) Length(2) Fragment(N).
    if payload.len() < 5 || payload[0] != 22 {
        return None;
    }
    // Bound the handshake fragment by the record-layer Length field so a
    // ClientHello that was fragmented across multiple TCP segments doesn't
    // get parsed past its captured boundary — reading the tail of an
    // unrelated segment would happily land on an ext_type=0 by coincidence
    // and emit a hostname built from garbage bytes.
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let hs_end = 5usize.checked_add(rec_len)?.min(payload.len());
    if hs_end < 5 + 4 {
        return None;
    }
    let hs = &payload[5..hs_end];
    // Handshake message: msg_type(1) length(3) ClientHello{...}.
    if hs[0] != 1 {
        return None;
    }
    let hs_body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let body_end = 4usize.checked_add(hs_body_len)?.min(hs.len());
    if body_end < 4 {
        return None;
    }
    let body = &hs[4..body_end];
    // ClientHello: version(2) random(32) session_id<u8> cipher_suites<u16>
    // compression_methods<u8> extensions<u16>.
    let mut i = 2 + 32;
    let sid_len = *body.get(i)? as usize;
    i = i.checked_add(1)?.checked_add(sid_len)?;
    let cs_len = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize;
    i = i.checked_add(2)?.checked_add(cs_len)?;
    let cm_len = *body.get(i)? as usize;
    i = i.checked_add(1)?.checked_add(cm_len)?;
    let ext_total = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize;
    i = i.checked_add(2)?;
    let end = (i.checked_add(ext_total)?).min(body.len());
    while i + 4 <= end {
        let ext_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let ext_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if ext_type == 0 {
            // server_name extension: list_len(u16) [name_type(u8)
            // host_name<u16>]
            if i + 2 > end {
                return None;
            }
            let _list_len = u16::from_be_bytes([body[i], body[i + 1]]);
            i += 2;
            if i + 3 > end || body[i] != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
            i += 3;
            if i + name_len > end {
                return None;
            }
            return std::str::from_utf8(&body[i..i + name_len])
                .ok()
                .map(str::to_string);
        }
        i += ext_len;
    }
    None
}
