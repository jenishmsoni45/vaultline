//! Reading passphrases and values (`docs/design.md` §4, D-011, D-012, D-029,
//! D-037, D-046).
//!
//! A passphrase comes from a hidden terminal prompt, or, with
//! `--passphrase-stdin`, from the first lines of standard input, one per line,
//! in the order the command asks for them. Everything after those lines is the
//! command's own input: the value for `set`, the template for `inject`, the
//! child's standard input for `run`. Lines are read one byte at a time from
//! the descriptor itself, with no buffering, so nothing beyond the newline is
//! consumed.
//!
//! Every buffer that holds a passphrase or a value is wiped when dropped, and
//! none of these types implements `Debug` or `Display`.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd;

use zeroize::{Zeroize, Zeroizing};

use crate::secret::{Passphrase, SecretValue};
use crate::vault::MAX_VALUE_LEN;

/// The shortest passphrase `init` and `passwd` accept, in characters (D-029,
/// D-046).
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// The longest passphrase line read from standard input, in bytes.
pub const MAX_PASSPHRASE_LEN: usize = 64 * 1024;

/// Why input couldn't be read or isn't acceptable. No variant holds a
/// passphrase or a value.
#[derive(Debug)]
pub enum InputError {
    /// Standard input ended before the passphrase line.
    NoPassphraseOnStdin,
    /// A passphrase line is longer than 64 KiB.
    LineTooLong,
    /// The terminal couldn't be used for a prompt.
    Terminal(io::Error),
    /// Reading standard input failed.
    Io(io::Error),
    /// A new passphrase has fewer than 12 characters.
    TooShort { characters: usize },
    /// A new passphrase isn't valid UTF-8, so its characters can't be counted.
    NotUtf8,
    /// The two entries of a new passphrase differ.
    Mismatch,
    /// A value is longer than 64 KiB.
    ValueTooLarge,
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::NoPassphraseOnStdin => f.write_str(
                "standard input ended before a passphrase line; \
                 with --passphrase-stdin the first line is the passphrase",
            ),
            InputError::LineTooLong => f.write_str("a passphrase can be at most 64 KiB"),
            InputError::Terminal(source) => write!(
                f,
                "can't read from the terminal: {source}; \
                 use --passphrase-stdin to read passphrases from standard input"
            ),
            InputError::Io(source) => write!(f, "can't read standard input: {source}"),
            InputError::TooShort { characters } => write!(
                f,
                "the passphrase has {characters} characters; it needs at least \
                 {MIN_PASSPHRASE_CHARS} (several random words work well)"
            ),
            InputError::NotUtf8 => f.write_str(
                "a new passphrase must be valid UTF-8, so that its characters can be counted",
            ),
            InputError::Mismatch => f.write_str("the two passphrases don't match"),
            InputError::ValueTooLarge => f.write_str("a value can be at most 64 KiB"),
        }
    }
}

impl std::error::Error for InputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InputError::Terminal(source) | InputError::Io(source) => Some(source),
            _ => None,
        }
    }
}

/// Standard input, read straight from descriptor 0 with no buffering. The
/// standard library's own `Stdin` buffers, and would swallow bytes that belong
/// to the child or to the template.
pub struct Stdin(File);

impl Stdin {
    /// A handle on descriptor 0.
    pub fn open() -> io::Result<Stdin> {
        Ok(Stdin(File::from(io::stdin().as_fd().try_clone_to_owned()?)))
    }

    /// Whether standard input is a terminal.
    pub fn is_terminal() -> bool {
        io::IsTerminal::is_terminal(&io::stdin())
    }
}

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// One line from `reader`, without its `\n`, reading a byte at a time and
/// stopping right after the newline. `None` means the input ended before any
/// byte. A last line without a newline is returned as it is.
pub fn read_line(reader: &mut impl Read) -> Result<Option<Zeroizing<Vec<u8>>>, InputError> {
    // The capacity is reserved once, so the line never moves to a new
    // allocation and leaves a stale copy behind.
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE_LEN));
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return Ok(if line.is_empty() { None } else { Some(line) });
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Ok(Some(line));
                }
                if line.len() >= MAX_PASSPHRASE_LEN {
                    return Err(InputError::LineTooLong);
                }
                line.push(byte[0]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(InputError::Io(e)),
        }
    }
}

/// Reads a value to the end of `reader`. Unless `raw`, one trailing `\n` is
/// removed (D-029). A value over 64 KiB is an error, and nothing past 64 KiB
/// is read into memory.
pub fn read_value(reader: &mut impl Read, raw: bool) -> Result<SecretValue, InputError> {
    // One byte of room for the newline, and one more to notice an overflow.
    let mut buf = Zeroizing::new(vec![0u8; MAX_VALUE_LEN + 2]);
    let mut filled = 0usize;
    while filled < buf.len() {
        let Some(room) = buf.get_mut(filled..) else {
            break;
        };
        match reader.read(room) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(InputError::Io(e)),
        }
    }
    let mut data = buf.get(..filled).unwrap_or_default();
    if !raw {
        data = data.strip_suffix(b"\n").unwrap_or(data);
    }
    if data.len() > MAX_VALUE_LEN {
        return Err(InputError::ValueTooLarge);
    }
    Ok(SecretValue::new(data))
}

/// Checks a new passphrase against the rules of D-029 and D-046: valid UTF-8,
/// and at least 12 characters.
pub fn check_new_passphrase(bytes: &[u8]) -> Result<(), InputError> {
    let text = std::str::from_utf8(bytes).map_err(|_| InputError::NotUtf8)?;
    let characters = text.chars().count();
    if characters < MIN_PASSPHRASE_CHARS {
        return Err(InputError::TooShort { characters });
    }
    Ok(())
}

/// Where passphrases come from for one command.
pub struct Passphrases {
    stdin: Option<Stdin>,
}

impl Passphrases {
    /// Passphrases from hidden terminal prompts.
    pub fn prompting() -> Passphrases {
        Passphrases { stdin: None }
    }

    /// Passphrases from the first lines of standard input.
    pub fn from_stdin() -> io::Result<Passphrases> {
        Ok(Passphrases {
            stdin: Some(Stdin::open()?),
        })
    }

    /// Whether `--passphrase-stdin` is in effect.
    pub fn reads_stdin(&self) -> bool {
        self.stdin.is_some()
    }

    /// The current passphrase, for opening a vault.
    pub fn ask(&mut self, prompt: &str) -> Result<Passphrase, InputError> {
        let bytes = self.next(prompt)?;
        Ok(Passphrase::new(&bytes))
    }

    /// A new passphrase, for `init` and `passwd`. From a terminal it is asked
    /// for twice. From standard input it is one line. Either way it must pass
    /// [`check_new_passphrase`].
    pub fn ask_new(&mut self, prompt: &str) -> Result<Passphrase, InputError> {
        let first = self.next(prompt)?;
        check_new_passphrase(&first)?;
        if self.stdin.is_none() {
            let second = self.next("Repeat the passphrase: ")?;
            if *first != *second {
                return Err(InputError::Mismatch);
            }
        }
        Ok(Passphrase::new(&first))
    }

    fn next(&mut self, prompt: &str) -> Result<Zeroizing<Vec<u8>>, InputError> {
        match &mut self.stdin {
            Some(stdin) => read_line(stdin)?.ok_or(InputError::NoPassphraseOnStdin),
            None => prompt_hidden(prompt),
        }
    }
}

/// A hidden prompt on the terminal (`/dev/tty`), not on standard output or
/// standard error, so it never mixes with what a command prints.
pub fn prompt_hidden(prompt: &str) -> Result<Zeroizing<Vec<u8>>, InputError> {
    let mut text = rpassword::prompt_password(prompt).map_err(InputError::Terminal)?;
    let bytes = Zeroizing::new(text.as_bytes().to_vec());
    text.zeroize();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn line(input: &[u8]) -> Option<Vec<u8>> {
        read_line(&mut Cursor::new(input))
            .unwrap()
            .map(|l| l.to_vec())
    }

    #[test]
    fn a_line_loses_its_newline_and_nothing_else() {
        assert_eq!(line(b"correct horse\n").unwrap(), b"correct horse");
        assert_eq!(line(b" spaced \n").unwrap(), b" spaced ");
        assert_eq!(line(b"tab\t\n").unwrap(), b"tab\t");
        // Only \n is a line terminator; a \r stays part of the passphrase.
        assert_eq!(line(b"windows\r\n").unwrap(), b"windows\r");
    }

    #[test]
    fn a_last_line_without_a_newline_is_returned() {
        assert_eq!(line(b"no newline").unwrap(), b"no newline");
    }

    #[test]
    fn an_empty_line_is_an_empty_passphrase_and_end_of_input_is_none() {
        assert_eq!(line(b"\nrest").unwrap(), b"");
        assert_eq!(line(b""), None);
    }

    #[test]
    fn reading_a_line_consumes_nothing_beyond_the_newline() {
        let mut input = Cursor::new(b"first\nsecond\nthe rest, which is not a passphrase".to_vec());
        assert_eq!(read_line(&mut input).unwrap().unwrap().to_vec(), b"first");
        assert_eq!(input.position(), 6);
        assert_eq!(read_line(&mut input).unwrap().unwrap().to_vec(), b"second");
        assert_eq!(input.position(), 13);
    }

    #[test]
    fn the_rest_of_the_input_is_still_there_on_a_real_descriptor() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"pass\nbody bytes").unwrap();
        drop(writer);
        assert_eq!(read_line(&mut reader).unwrap().unwrap().to_vec(), b"pass");
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"body bytes");
    }

    #[test]
    fn a_passphrase_line_over_64_kib_is_an_error() {
        let mut long = vec![b'a'; MAX_PASSPHRASE_LEN];
        assert!(read_line(&mut Cursor::new(&long)).unwrap().is_some());
        long.push(b'a');
        assert!(matches!(
            read_line(&mut Cursor::new(&long)),
            Err(InputError::LineTooLong)
        ));
    }

    fn value(input: &[u8], raw: bool) -> Result<Vec<u8>, InputError> {
        read_value(&mut Cursor::new(input), raw).map(|v| v.expose().to_vec())
    }

    #[test]
    fn a_value_loses_one_trailing_newline_unless_raw() {
        assert_eq!(value(b"abc\n", false).unwrap(), b"abc");
        assert_eq!(value(b"abc\n\n", false).unwrap(), b"abc\n");
        assert_eq!(value(b"abc", false).unwrap(), b"abc");
        assert_eq!(value(b"abc\n", true).unwrap(), b"abc\n");
        assert_eq!(value(b"abc\r\n", false).unwrap(), b"abc\r");
        assert_eq!(value(b"\n", false).unwrap(), b"");
        assert_eq!(value(b"", false).unwrap(), b"");
    }

    #[test]
    fn a_value_can_hold_any_bytes_including_newlines() {
        assert_eq!(value(b"a\nb\x00\xff", false).unwrap(), b"a\nb\x00\xff");
    }

    #[test]
    fn a_value_is_limited_to_64_kib() {
        let ok = vec![b'v'; MAX_VALUE_LEN];
        assert_eq!(value(&ok, false).unwrap().len(), MAX_VALUE_LEN);
        assert_eq!(value(&ok, true).unwrap().len(), MAX_VALUE_LEN);
        // The newline doesn't count towards the limit unless it is kept.
        let mut with_newline = ok.clone();
        with_newline.push(b'\n');
        assert_eq!(value(&with_newline, false).unwrap().len(), MAX_VALUE_LEN);
        assert!(matches!(
            value(&with_newline, true),
            Err(InputError::ValueTooLarge)
        ));
        let too_big = vec![b'v'; MAX_VALUE_LEN + 1];
        assert!(matches!(
            value(&too_big, false),
            Err(InputError::ValueTooLarge)
        ));
        let way_too_big = vec![b'v'; 10 * MAX_VALUE_LEN];
        assert!(matches!(
            value(&way_too_big, false),
            Err(InputError::ValueTooLarge)
        ));
    }

    #[test]
    fn a_new_passphrase_needs_twelve_characters_not_bytes() {
        assert!(check_new_passphrase(b"exactly12chr").is_ok());
        assert!(matches!(
            check_new_passphrase(b"only11chars"),
            Err(InputError::TooShort { characters: 11 })
        ));
        assert!(matches!(
            check_new_passphrase(b""),
            Err(InputError::TooShort { characters: 0 })
        ));
        // 4 characters of 3 bytes each is 12 bytes but only 4 characters.
        assert!(matches!(
            check_new_passphrase("\u{20ac}\u{20ac}\u{20ac}\u{20ac}".as_bytes()),
            Err(InputError::TooShort { characters: 4 })
        ));
        // 12 two-byte characters pass.
        assert!(check_new_passphrase("\u{e9}".repeat(12).as_bytes()).is_ok());
    }

    #[test]
    fn a_new_passphrase_must_be_utf8() {
        assert!(matches!(
            check_new_passphrase(&[0xff; 20]),
            Err(InputError::NotUtf8)
        ));
    }

    #[test]
    fn error_messages_never_contain_the_input() {
        let secret = "fake-passphrase-9f3a";
        let message = check_new_passphrase(&secret.as_bytes()[..11])
            .unwrap_err()
            .to_string();
        assert!(!message.contains("fake"), "{message}");
    }
}
