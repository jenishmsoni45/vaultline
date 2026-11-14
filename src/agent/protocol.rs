//! The agent's wire protocol, version 1 (`docs/design.md` §8.1, D-027).
//!
//! ```text
//! frame = length:u32 body            1 <= length <= 1 MiB
//! body  = proto_version:u8 (= 1) kind:u8 fields
//! str   = len:u16 bytes              references, project names, messages
//! blob  = len:u32 bytes              values and passphrases, at most 64 KiB
//! ```
//!
//! Integers are little-endian, like every other format in vaultline
//! (`vault-format.md` §1). One request per connection, and one response. A
//! response is `proto_version:u8 status:u8` (0 OK, 1 error), then the fields of
//! the request's OK reply, or `code:u16 str` for an error.
//!
//! Everything here reads bytes from a peer that may be hostile, so there is no
//! `unwrap`, indexing or unchecked arithmetic. A frame that is too long or too
//! short, has an unknown kind or version, carries bytes after its last field,
//! or has a length that overruns it is rejected as a whole. Buffers that hold
//! passphrases or values are wiped when dropped, and the types that hold them
//! implement neither `Debug` nor `Display`.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::fmt;
use std::io::{self, Read};

use zeroize::Zeroizing;

use crate::secret::{Passphrase, SecretValue};

/// The only protocol version.
pub const PROTO_VERSION: u8 = 1;
/// The most a frame's body may hold (1 MiB).
pub const MAX_FRAME: usize = 1024 * 1024;
/// The most a value or a passphrase may hold (64 KiB).
pub const MAX_BLOB: usize = 64 * 1024;

const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;

/// Error codes of an error response. The message next to the code is what a
/// person reads; it never holds a secret.
pub mod code {
    /// The agent is locked.
    pub const LOCKED: u16 = 1;
    /// A reference names nothing. The message is the reference.
    pub const NOT_FOUND: u16 = 2;
    /// The request can't be served as asked.
    pub const BAD_REQUEST: u16 = 3;
    /// The vault or the audit log refused.
    pub const VAULT: u16 = 4;
    /// The answer wouldn't fit in a frame.
    pub const TOO_LARGE: u16 = 5;
    /// Another vaultline held the writer lock for too long.
    pub const BUSY: u16 = 6;
}

/// What can be wrong with a frame.
#[derive(Debug)]
pub enum ProtocolError {
    /// A length or a field runs past the end of the frame.
    Truncated,
    /// Bytes are left after the last field.
    TrailingBytes,
    /// A frame of length 0, or longer than 1 MiB.
    BadLength,
    /// A kind this version doesn't have.
    UnknownKind(u8),
    /// A protocol version other than 1.
    UnsupportedVersion(u8),
    /// A status other than 0 or 1.
    UnknownStatus(u8),
    /// A flag byte other than 0 or 1.
    BadFlag,
    /// A value or passphrase longer than 64 KiB, or a field too long to encode.
    TooLarge,
    /// A text field that isn't UTF-8.
    NotUtf8,
    /// Reading the frame failed, or timed out.
    Io(io::Error),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Truncated => f.write_str("a field runs past the end of the message"),
            ProtocolError::TrailingBytes => {
                f.write_str("the message has bytes after its last field")
            }
            ProtocolError::BadLength => f.write_str("a message must be between 1 byte and 1 MiB"),
            ProtocolError::UnknownKind(kind) => write!(f, "unknown message kind {kind}"),
            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            ProtocolError::UnknownStatus(s) => write!(f, "unknown status {s}"),
            ProtocolError::BadFlag => f.write_str("a flag byte is neither 0 nor 1"),
            ProtocolError::TooLarge => f.write_str("a field is too large for the message format"),
            ProtocolError::NotUtf8 => f.write_str("a text field is not valid UTF-8"),
            ProtocolError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// The kind byte of a request (§8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Resolve = 1,
    Set = 2,
    Remove = 3,
    List = 4,
    Unlock = 5,
    Lock = 6,
    Stop = 7,
    Status = 8,
    AuditVerify = 9,
    AuditHead = 10,
}

impl Kind {
    pub fn from_code(code: u8) -> Option<Kind> {
        Some(match code {
            1 => Kind::Resolve,
            2 => Kind::Set,
            3 => Kind::Remove,
            4 => Kind::List,
            5 => Kind::Unlock,
            6 => Kind::Lock,
            7 => Kind::Stop,
            8 => Kind::Status,
            9 => Kind::AuditVerify,
            10 => Kind::AuditHead,
            _ => return None,
        })
    }

    /// Every kind, for tests and the fuzz target.
    pub const ALL: [Kind; 10] = [
        Kind::Resolve,
        Kind::Set,
        Kind::Remove,
        Kind::List,
        Kind::Unlock,
        Kind::Lock,
        Kind::Stop,
        Kind::Status,
        Kind::AuditVerify,
        Kind::AuditHead,
    ];
}

/// A request. It may hold a value or a passphrase, so it implements neither
/// `Debug` nor `Display`.
pub enum Request {
    /// References, as bytes: parsing them is the server's job.
    Resolve(Vec<Vec<u8>>),
    Set {
        reference: Vec<u8>,
        value: SecretValue,
    },
    Remove(Vec<u8>),
    List(Option<Vec<u8>>),
    Unlock(Passphrase),
    Lock,
    Stop,
    Status,
    /// An anchor, as text bytes, if `--expect` was given.
    AuditVerify(Option<Vec<u8>>),
    AuditHead,
}

impl Request {
    pub fn kind(&self) -> Kind {
        match self {
            Request::Resolve(_) => Kind::Resolve,
            Request::Set { .. } => Kind::Set,
            Request::Remove(_) => Kind::Remove,
            Request::List(_) => Kind::List,
            Request::Unlock(_) => Kind::Unlock,
            Request::Lock => Kind::Lock,
            Request::Stop => Kind::Stop,
            Request::Status => Kind::Status,
            Request::AuditVerify(_) => Kind::AuditVerify,
            Request::AuditHead => Kind::AuditHead,
        }
    }
}

/// The fields of an OK response. Which one it is follows from the request.
pub enum Reply {
    /// For Resolve: the values, in the order of the request.
    Values(Vec<SecretValue>),
    /// For Set, Remove, Unlock, Lock and Stop: nothing.
    Done,
    /// For List: `project/item/field` names.
    Names(Vec<String>),
    /// For Status.
    Status { unlocked: bool, idle_secs: u32 },
    /// For AuditVerify.
    Verdict { passed: bool, report: String },
    /// For AuditHead: `count:hash`.
    Anchor(String),
}

/// A response: an OK reply, or an error.
pub enum Response {
    Ok(Reply),
    Err { code: u16, message: String },
}

impl Response {
    pub fn error(code: u16, message: impl Into<String>) -> Response {
        Response::Err {
            code,
            message: message.into(),
        }
    }
}

/// A writer that refuses to grow past the frame limit, into a buffer that is
/// wiped when dropped. Its capacity is reserved first, so a secret is never
/// copied by a reallocation that leaves the old copy behind.
struct Body(Zeroizing<Vec<u8>>);

impl Body {
    fn new(capacity: usize) -> Body {
        Body(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    fn put(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn u8(&mut self, value: u8) {
        self.put(&[value]);
    }

    fn u16(&mut self, value: u16) {
        self.put(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.put(&value.to_le_bytes());
    }

    fn flag(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn str(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let len = u16::try_from(bytes.len()).map_err(|_| ProtocolError::TooLarge)?;
        self.u16(len);
        self.put(bytes);
        Ok(())
    }

    fn blob(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        if bytes.len() > MAX_BLOB {
            return Err(ProtocolError::TooLarge);
        }
        let len = u32::try_from(bytes.len()).map_err(|_| ProtocolError::TooLarge)?;
        self.u32(len);
        self.put(bytes);
        Ok(())
    }

    /// The whole frame: the length, then the body.
    fn frame(self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let len = self.0.len();
        if len == 0 || len > MAX_FRAME {
            return Err(ProtocolError::TooLarge);
        }
        let prefix = u32::try_from(len).map_err(|_| ProtocolError::TooLarge)?;
        let mut frame = Zeroizing::new(Vec::with_capacity(len.saturating_add(4)));
        frame.extend_from_slice(&prefix.to_le_bytes());
        frame.extend_from_slice(&self.0);
        Ok(frame)
    }
}

/// Reads fields from a frame body.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(ProtocolError::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        match self.take(1)? {
            [byte] => Ok(*byte),
            _ => Err(ProtocolError::Truncated),
        }
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn flag(&mut self) -> Result<bool, ProtocolError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtocolError::BadFlag),
        }
    }

    fn str(&mut self) -> Result<&'a [u8], ProtocolError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    fn text(&mut self) -> Result<String, ProtocolError> {
        String::from_utf8(self.str()?.to_vec()).map_err(|_| ProtocolError::NotUtf8)
    }

    fn blob(&mut self) -> Result<&'a [u8], ProtocolError> {
        let len = usize::try_from(self.u32()?).map_err(|_| ProtocolError::TooLarge)?;
        if len > MAX_BLOB {
            return Err(ProtocolError::TooLarge);
        }
        self.take(len)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Fails if any bytes are left.
    fn finish(self) -> Result<(), ProtocolError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

/// Reads one frame from `reader` and returns its body, wiped on drop. The
/// length is checked before anything is allocated for the body.
pub fn read_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).map_err(ProtocolError::Io)?;
    let len = usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| ProtocolError::BadLength)?;
    if len == 0 || len > MAX_FRAME {
        return Err(ProtocolError::BadLength);
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body).map_err(ProtocolError::Io)?;
    Ok(body)
}

/// A request as a whole frame, ready to write.
pub fn encode_request(request: &Request) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut body = Body::new(request_capacity(request));
    body.u8(PROTO_VERSION);
    body.u8(request.kind() as u8);
    match request {
        Request::Resolve(references) => {
            let count = u16::try_from(references.len()).map_err(|_| ProtocolError::TooLarge)?;
            body.u16(count);
            for reference in references {
                body.str(reference)?;
            }
        }
        Request::Set { reference, value } => {
            body.str(reference)?;
            body.blob(value.expose())?;
        }
        Request::Remove(reference) => body.str(reference)?,
        Request::List(project) => {
            body.flag(project.is_some());
            if let Some(project) = project {
                body.str(project)?;
            }
        }
        Request::Unlock(passphrase) => body.blob(passphrase.expose())?,
        Request::Lock | Request::Stop | Request::Status | Request::AuditHead => {}
        Request::AuditVerify(expect) => {
            body.flag(expect.is_some());
            if let Some(anchor) = expect {
                body.str(anchor)?;
            }
        }
    }
    body.frame()
}

/// What an encoded request needs, so the buffer never reallocates.
fn request_capacity(request: &Request) -> usize {
    let fields = match request {
        Request::Resolve(references) => references
            .iter()
            .fold(2usize, |n, r| n.saturating_add(r.len()).saturating_add(2)),
        Request::Set { reference, value } => reference
            .len()
            .saturating_add(value.len())
            .saturating_add(6),
        Request::Remove(reference) => reference.len().saturating_add(2),
        Request::List(project) | Request::AuditVerify(project) => {
            project.as_ref().map_or(1, |p| p.len().saturating_add(3))
        }
        Request::Unlock(passphrase) => passphrase.expose().len().saturating_add(4),
        Request::Lock | Request::Stop | Request::Status | Request::AuditHead => 0,
    };
    fields.saturating_add(2).min(MAX_FRAME)
}

/// Parses a request body (what [`read_frame`] returns).
pub fn decode_request(body: &[u8]) -> Result<Request, ProtocolError> {
    let mut cursor = Cursor(body);
    let version = cursor.u8()?;
    if version != PROTO_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let code = cursor.u8()?;
    let kind = Kind::from_code(code).ok_or(ProtocolError::UnknownKind(code))?;
    let request = match kind {
        Kind::Resolve => {
            let count = usize::from(cursor.u16()?);
            // Each reference takes at least its two length bytes, so a count
            // the frame can't hold is caught before anything is reserved.
            let mut references = Vec::with_capacity(count.min(cursor.0.len() / 2));
            for _ in 0..count {
                references.push(cursor.str()?.to_vec());
            }
            Request::Resolve(references)
        }
        Kind::Set => Request::Set {
            reference: cursor.str()?.to_vec(),
            value: SecretValue::new(cursor.blob()?),
        },
        Kind::Remove => Request::Remove(cursor.str()?.to_vec()),
        Kind::List => Request::List(optional_str(&mut cursor)?),
        Kind::Unlock => Request::Unlock(Passphrase::new(cursor.blob()?)),
        Kind::Lock => Request::Lock,
        Kind::Stop => Request::Stop,
        Kind::Status => Request::Status,
        Kind::AuditVerify => Request::AuditVerify(optional_str(&mut cursor)?),
        Kind::AuditHead => Request::AuditHead,
    };
    cursor.finish()?;
    Ok(request)
}

fn optional_str(cursor: &mut Cursor<'_>) -> Result<Option<Vec<u8>>, ProtocolError> {
    if cursor.flag()? {
        Ok(Some(cursor.str()?.to_vec()))
    } else {
        Ok(None)
    }
}

/// A response as a whole frame, ready to write.
pub fn encode_response(response: &Response) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let capacity = match response {
        Response::Ok(Reply::Values(values)) => values
            .iter()
            .fold(2usize, |n, v| n.saturating_add(v.len()).saturating_add(4)),
        Response::Ok(Reply::Names(names)) => names
            .iter()
            .fold(6usize, |n, s| n.saturating_add(s.len()).saturating_add(2)),
        Response::Ok(Reply::Verdict { report: text, .. } | Reply::Anchor(text)) => {
            text.len().saturating_add(5)
        }
        Response::Err { message, .. } => message.len().saturating_add(6),
        Response::Ok(_) => 8,
    }
    .min(MAX_FRAME);
    let mut body = Body::new(capacity);
    body.u8(PROTO_VERSION);
    match response {
        Response::Ok(reply) => {
            body.u8(STATUS_OK);
            match reply {
                Reply::Values(values) => {
                    for value in values {
                        body.blob(value.expose())?;
                    }
                }
                Reply::Done => {}
                Reply::Names(names) => {
                    let count = u32::try_from(names.len()).map_err(|_| ProtocolError::TooLarge)?;
                    body.u32(count);
                    for name in names {
                        body.str(name.as_bytes())?;
                    }
                }
                Reply::Status {
                    unlocked,
                    idle_secs,
                } => {
                    body.flag(*unlocked);
                    body.u32(*idle_secs);
                }
                Reply::Verdict { passed, report } => {
                    body.flag(*passed);
                    body.str(report.as_bytes())?;
                }
                Reply::Anchor(anchor) => body.str(anchor.as_bytes())?,
            }
        }
        Response::Err { code, message } => {
            body.u8(STATUS_ERROR);
            body.u16(*code);
            body.str(message.as_bytes())?;
        }
    }
    body.frame()
}

/// Parses a response body to a request of `kind`: the layout of an OK reply
/// depends on the request it answers.
pub fn decode_response(kind: Kind, body: &[u8]) -> Result<Response, ProtocolError> {
    let mut cursor = Cursor(body);
    let version = cursor.u8()?;
    if version != PROTO_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let response = match cursor.u8()? {
        STATUS_OK => Response::Ok(match kind {
            Kind::Resolve => {
                let mut values = Vec::new();
                while !cursor.is_empty() {
                    values.push(SecretValue::new(cursor.blob()?));
                }
                Reply::Values(values)
            }
            Kind::Set | Kind::Remove | Kind::Unlock | Kind::Lock | Kind::Stop => Reply::Done,
            Kind::List => {
                let count = usize::try_from(cursor.u32()?).map_err(|_| ProtocolError::TooLarge)?;
                let mut names = Vec::with_capacity(count.min(cursor.0.len() / 2));
                for _ in 0..count {
                    names.push(cursor.text()?);
                }
                Reply::Names(names)
            }
            Kind::Status => Reply::Status {
                unlocked: cursor.flag()?,
                idle_secs: cursor.u32()?,
            },
            Kind::AuditVerify => Reply::Verdict {
                passed: cursor.flag()?,
                report: cursor.text()?,
            },
            Kind::AuditHead => Reply::Anchor(cursor.text()?),
        }),
        STATUS_ERROR => Response::Err {
            code: cursor.u16()?,
            message: cursor.text()?,
        },
        other => return Err(ProtocolError::UnknownStatus(other)),
    };
    cursor.finish()?;
    Ok(response)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests;
