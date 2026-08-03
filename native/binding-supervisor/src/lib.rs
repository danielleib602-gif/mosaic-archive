//! Portable protocol and validation core for the Linux binding supervisor.
//!
//! This crate deliberately does not launch workloads and does not establish
//! competitive-binding authority.  Its first native slice only creates and
//! hands off an exclusive delegated cgroup subtree.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod linux;

pub const CONTROL_PACKET_BYTES: usize = 88;
/// Coordinator-to-supervisor readiness datagram sent after enabling `SO_PASSCRED`.
pub const CONTROL_READY: u8 = b'R';
/// Supervisor-to-coordinator revocation datagram sent before signal-driven cleanup.
pub const CONTROL_REVOKE: u8 = b'X';
pub const PROTOCOL_MAGIC: [u8; 8] = *b"MSCBIND1";
pub const PROTOCOL_VERSION: u16 = 1;
pub const PROTOCOL_FLAGS: u16 = 0;
pub const SESSION_PREFIX: &str = "mosaic-supervisor-";
pub const LEAF_PREFIX: &str = "mosaic-binding-";
pub const MAX_CGROUP_NAME_BYTES: usize = 255;
pub const MAX_CONTROL_BYTES: usize = 64 * 1024;
pub const RUNNER_POLICY_SHA256: [u8; 32] = [
    0xbd, 0x80, 0x39, 0x11, 0x9e, 0x7a, 0xb1, 0x7b, 0x57, 0x76, 0xfd, 0x20, 0x25, 0x53, 0x1f, 0xf2,
    0xcd, 0x22, 0x75, 0xce, 0x13, 0xc9, 0x12, 0x40, 0x57, 0x92, 0xee, 0xcc, 0x09, 0x38, 0x8e, 0x58,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffPacket {
    pub sender_pid: u32,
    pub sender_uid: u32,
    pub sender_gid: u32,
    pub root_device: u64,
    pub root_inode: u64,
    pub session_nonce: [u8; 16],
}

impl HandoffPacket {
    #[must_use]
    pub fn encode(self) -> [u8; CONTROL_PACKET_BYTES] {
        let mut packet = [0_u8; CONTROL_PACKET_BYTES];
        packet[0..8].copy_from_slice(&PROTOCOL_MAGIC);
        packet[8..10].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        packet[10..12].copy_from_slice(&PROTOCOL_FLAGS.to_be_bytes());
        packet[12..16].copy_from_slice(&self.sender_pid.to_be_bytes());
        packet[16..20].copy_from_slice(&self.sender_uid.to_be_bytes());
        packet[20..24].copy_from_slice(&self.sender_gid.to_be_bytes());
        packet[24..32].copy_from_slice(&self.root_device.to_be_bytes());
        packet[32..40].copy_from_slice(&self.root_inode.to_be_bytes());
        packet[40..72].copy_from_slice(&RUNNER_POLICY_SHA256);
        packet[72..88].copy_from_slice(&self.session_nonce);
        packet
    }
}

#[must_use]
pub fn session_name(nonce: &[u8; 16]) -> String {
    let mut name = String::with_capacity(SESSION_PREFIX.len() + 32);
    name.push_str(SESSION_PREFIX);
    for byte in nonce {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    name
}

#[must_use]
pub fn is_valid_session_nonce(nonce: &[u8; 16]) -> bool {
    nonce.iter().any(|byte| *byte != 0)
}

#[must_use]
pub fn is_valid_session_name(name: &[u8]) -> bool {
    name.len() == SESSION_PREFIX.len() + 32
        && name.starts_with(SESSION_PREFIX.as_bytes())
        && name[SESSION_PREFIX.len()..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[must_use]
pub fn is_valid_leaf_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CGROUP_NAME_BYTES
        && name.starts_with(LEAF_PREFIX.as_bytes())
        && name != b"."
        && name != b".."
        && name[0].is_ascii_lowercase()
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseControlError(&'static str);

impl ParseControlError {
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.0
    }
}

impl Display for ParseControlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for ParseControlError {}

fn exact_lines(bytes: &[u8]) -> Result<Vec<&str>, ParseControlError> {
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
        return Err(ParseControlError("control text has an invalid byte length"));
    }
    if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') || bytes.contains(&0) {
        return Err(ParseControlError(
            "control text is not exact LF-terminated text",
        ));
    }
    let body = &bytes[..bytes.len() - 1];
    if body.is_empty()
        || body.contains(&b'\n') && body.split(|byte| *byte == b'\n').any(<[u8]>::is_empty)
    {
        return Err(ParseControlError("control text contains an empty line"));
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| ParseControlError("control text is not valid UTF-8"))?;
    if !text.is_ascii() {
        return Err(ParseControlError("control text is not ASCII"));
    }
    Ok(text.split('\n').collect())
}

/// Parse one non-empty ASCII line with exactly one trailing LF.
///
/// # Errors
///
/// Returns an error for oversized, unterminated, non-ASCII, or multi-line input.
pub fn parse_single_line(bytes: &[u8]) -> Result<&str, ParseControlError> {
    let lines = exact_lines(bytes)?;
    if lines.len() != 1 {
        return Err(ParseControlError("control text is not exactly one line"));
    }
    Ok(lines[0])
}

/// Parse a kernel cgroup controller list without accepting duplicate or ambiguous tokens.
///
/// # Errors
///
/// Returns an error when the bounded line or any controller token is non-canonical.
pub fn parse_controller_set(bytes: &[u8]) -> Result<BTreeSet<String>, ParseControlError> {
    let line = parse_single_line(bytes)?;
    let mut result = BTreeSet::new();
    for token in line.split(' ') {
        if token.is_empty()
            || !token.as_bytes()[0].is_ascii_lowercase()
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(ParseControlError(
                "controller list has invalid token syntax",
            ));
        }
        if !result.insert(token.to_owned()) {
            return Err(ParseControlError("controller list repeats a token"));
        }
    }
    Ok(result)
}

/// Parse the unique `populated` field from exact bounded `cgroup.events` text.
///
/// # Errors
///
/// Returns an error for malformed fields, duplicate keys, or a missing/non-boolean
/// `populated` value.
pub fn parse_populated(bytes: &[u8]) -> Result<bool, ParseControlError> {
    let lines = exact_lines(bytes)?;
    let mut keys = BTreeSet::new();
    let mut populated = None;
    for line in lines {
        let (key, value) = line
            .split_once(' ')
            .ok_or(ParseControlError("cgroup.events line lacks one separator"))?;
        if key.is_empty()
            || value.is_empty()
            || value.contains(' ')
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || !is_canonical_unsigned(value)
        {
            return Err(ParseControlError("cgroup.events has invalid line syntax"));
        }
        if !keys.insert(key) {
            return Err(ParseControlError("cgroup.events repeats a key"));
        }
        if key == "populated" {
            populated = match value {
                "0" => Some(false),
                "1" => Some(true),
                _ => {
                    return Err(ParseControlError(
                        "cgroup.events populated is not zero or one",
                    ));
                }
            };
        }
    }
    populated.ok_or(ParseControlError("cgroup.events lacks populated"))
}

fn is_canonical_unsigned(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.parse::<u64>().is_ok()
}

/// Parse a canonical, strictly ordered cpuset ID list into inclusive ranges.
///
/// # Errors
///
/// Returns an error for malformed, non-canonical, overlapping, descending, or
/// out-of-range components.
pub fn parse_id_set(bytes: &[u8]) -> Result<Vec<(u32, u32)>, ParseControlError> {
    let line = parse_single_line(bytes)?;
    let mut ranges = Vec::new();
    let mut previous_end = None;
    for component in line.split(',') {
        if component.is_empty() {
            return Err(ParseControlError("ID set contains an empty component"));
        }
        let (start_text, end_text) = component
            .split_once('-')
            .map_or((component, component), |(start, end)| (start, end));
        if start_text.contains('-') || end_text.contains('-') {
            return Err(ParseControlError("ID set range has too many separators"));
        }
        let start = parse_canonical_u32(start_text)?;
        let end = parse_canonical_u32(end_text)?;
        if end < start {
            return Err(ParseControlError("ID set range is descending"));
        }
        if start == end && component.contains('-') {
            return Err(ParseControlError("ID set uses a redundant singleton range"));
        }
        if previous_end.is_some_and(|previous| start <= previous) {
            return Err(ParseControlError(
                "ID set is not strictly ordered and disjoint",
            ));
        }
        previous_end = Some(end);
        ranges.push((start, end));
    }
    Ok(ranges)
}

fn parse_canonical_u32(value: &str) -> Result<u32, ParseControlError> {
    if !is_canonical_unsigned(value) {
        return Err(ParseControlError(
            "ID set number is not canonical unsigned text",
        ));
    }
    value
        .parse::<u32>()
        .map_err(|_| ParseControlError("ID set number exceeds u32"))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CleanupFailures(Vec<String>);

impl CleanupFailures {
    pub fn record(&mut self, context: &str, result: Result<(), impl Display>) {
        if let Err(error) = result {
            self.0.push(format!("{context}: {error}"));
        }
    }

    pub fn push(&mut self, message: impl Into<String>) {
        self.0.push(message.into());
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleError {
    pub primary: Option<String>,
    pub cleanup: Vec<String>,
}

impl Display for LifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match &self.primary {
            Some(primary) => write!(formatter, "primary failure: {primary}")?,
            None => formatter.write_str("cleanup failure")?,
        }
        for cleanup in &self.cleanup {
            write!(formatter, "; cleanup failure: {cleanup}")?;
        }
        Ok(())
    }
}

impl Error for LifecycleError {}

/// Combine one primary result with every recorded cleanup failure.
///
/// # Errors
///
/// Returns a [`LifecycleError`] whenever either the primary operation or any
/// cleanup operation failed.
pub fn finish_lifecycle(
    primary: Result<(), impl Display>,
    cleanup: CleanupFailures,
) -> Result<(), LifecycleError> {
    let primary = primary.err().map(|error| error.to_string());
    let cleanup = cleanup.into_vec();
    if primary.is_none() && cleanup.is_empty() {
        Ok(())
    } else {
        Err(LifecycleError { primary, cleanup })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_packet_has_exact_big_endian_layout() {
        let packet = HandoffPacket {
            sender_pid: 0x0102_0304,
            sender_uid: 0x1112_1314,
            sender_gid: 0x2122_2324,
            root_device: 0x3132_3334_3536_3738,
            root_inode: 0x4142_4344_4546_4748,
            session_nonce: [0xa5; 16],
        }
        .encode();

        assert_eq!(packet.len(), CONTROL_PACKET_BYTES);
        assert_eq!(&packet[0..8], b"MSCBIND1");
        assert_eq!(&packet[8..12], &[0, 1, 0, 0]);
        assert_eq!(&packet[12..16], &[1, 2, 3, 4]);
        assert_eq!(&packet[16..20], &[0x11, 0x12, 0x13, 0x14]);
        assert_eq!(&packet[20..24], &[0x21, 0x22, 0x23, 0x24]);
        assert_eq!(
            &packet[24..32],
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        );
        assert_eq!(
            &packet[32..40],
            &[0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]
        );
        assert_eq!(&packet[40..72], &RUNNER_POLICY_SHA256);
        assert_eq!(&packet[72..88], &[0xa5; 16]);
    }

    #[test]
    fn session_name_is_lowercase_hex_and_exact() {
        let nonce = [
            0x00, 0x01, 0x0a, 0x0f, 0x10, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3,
            0xb4, 0xff,
        ];
        let name = session_name(&nonce);
        assert_eq!(name, "mosaic-supervisor-00010a0f102b3c4d5e6f708192a3b4ff");
        assert!(is_valid_session_name(name.as_bytes()));
        assert!(!is_valid_session_name(
            b"mosaic-supervisor-ABCDEF00000000000000000000000000"
        ));
        assert!(!is_valid_session_name(b"mosaic-supervisor-00"));
        assert!(is_valid_session_nonce(&nonce));
        assert!(!is_valid_session_nonce(&[0; 16]));
    }

    #[test]
    fn leaf_names_stay_in_the_fixed_safe_namespace() {
        assert!(is_valid_leaf_name(b"mosaic-binding-run-17_foo.bar"));
        assert!(is_valid_leaf_name(b"mosaic-binding-"));
        assert!(!is_valid_leaf_name(b"other-binding-run"));
        assert!(!is_valid_leaf_name(b"mosaic-binding-../escape"));
        assert!(!is_valid_leaf_name(b"mosaic-binding-UPPER"));
        assert!(!is_valid_leaf_name(&vec![b'a'; MAX_CGROUP_NAME_BYTES + 1]));
    }

    #[test]
    fn exact_text_parsers_accept_kernel_shapes() {
        assert_eq!(parse_single_line(b"domain\n"), Ok("domain"));
        assert_eq!(
            parse_controller_set(b"cpuset memory pids\n").unwrap(),
            BTreeSet::from(["cpuset".to_owned(), "memory".to_owned(), "pids".to_owned()])
        );
        assert!(!parse_populated(b"populated 0\nfrozen 0\n").unwrap());
        assert!(parse_populated(b"populated 1\nfrozen 0\n").unwrap());
        assert_eq!(
            parse_id_set(b"0-3,8,10-12\n").unwrap(),
            vec![(0, 3), (8, 8), (10, 12)]
        );
    }

    #[test]
    fn exact_text_parsers_reject_ambiguous_or_unbounded_inputs() {
        for invalid in [
            b"domain".as_slice(),
            b"domain\r\n",
            b"domain\nextra\n",
            b"domain\n\n",
            b"\n",
            b"do\0main\n",
        ] {
            assert!(parse_single_line(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(parse_single_line(&vec![b'x'; MAX_CONTROL_BYTES + 1]).is_err());
        assert!(parse_controller_set(b"cpuset  memory\n").is_err());
        assert!(parse_controller_set(b"cpuset cpuset\n").is_err());
        assert!(parse_populated(b"populated 0\npopulated 1\n").is_err());
        assert!(parse_populated(b"frozen 0\n").is_err());
        assert!(parse_populated(b"populated 00\n").is_err());
        assert!(parse_id_set(b"01\n").is_err());
        assert!(parse_id_set(b"3-3\n").is_err());
        assert!(parse_id_set(b"3,2\n").is_err());
        assert!(parse_id_set(b"1-3,3-4\n").is_err());
    }

    #[test]
    fn lifecycle_preserves_primary_and_all_cleanup_failures() {
        let mut cleanup = CleanupFailures::default();
        cleanup.record("kill", Err("permission denied"));
        cleanup.record("remove", Err("still populated"));
        let error = finish_lifecycle(Err("control socket failed"), cleanup).unwrap_err();
        assert_eq!(error.primary.as_deref(), Some("control socket failed"));
        assert_eq!(
            error.cleanup,
            ["kill: permission denied", "remove: still populated"]
        );
        assert!(error.to_string().contains("primary failure"));
    }

    #[test]
    fn cleanup_failure_prevents_clean_success() {
        let mut cleanup = CleanupFailures::default();
        cleanup.record("remove session", Err("busy"));
        let error = finish_lifecycle(Ok::<(), &str>(()), cleanup).unwrap_err();
        assert_eq!(error.primary, None);
        assert_eq!(error.cleanup, ["remove session: busy"]);
    }
}
