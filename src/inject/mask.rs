//! The streaming masker (`docs/design.md` §6, D-007, D-028, D-045).
//!
//! One [`Masker`] sits between one of the child's output pipes and the matching
//! stream of vaultline. It replaces every occurrence of every secret, however
//! the output is cut into chunks (S7): each maximal run of covered bytes
//! becomes one [`MARKER`], and every other byte passes through unchanged.
//!
//! How it works, per chunk:
//!
//! 1. The chunk is appended to the held bytes, and `aho-corasick` finds every
//!    occurrence in them, overlapping ones included. Bytes that an earlier
//!    chunk's match already covered count as covered (`carried`).
//! 2. `h` is the start of the longest tail that is a proper prefix of some
//!    secret. Every byte before `h` is final: an occurrence that covers it has
//!    already completed, because one that hadn't would start a longer pending
//!    tail. Those bytes are written, each covered run as one marker.
//! 3. The bytes from `h` on are held. Fewer than the longest secret are ever
//!    held (NFR-10), so memory is bounded whatever the child prints.
//!
//! The held bytes live in one buffer whose capacity is reserved up front, so it
//! never reallocates and leaves no stray copy behind, and they are wiped on
//! drop and whenever bytes leave the buffer. The automaton and the failure
//! tables are copies of the secrets that vaultline can't wipe (threat model
//! R6).
//!
//! The child's output is untrusted (S10): no `unwrap`, `expect`, indexing,
//! `panic` or unchecked arithmetic, enforced by the lints below.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use zeroize::{Zeroize, Zeroizing};

use crate::secret::SecretValue;

/// What every covered run is replaced by (D-028).
pub const MARKER: &[u8] = b"<concealed by vaultline>";

/// Input is processed in pieces of at most this many bytes, which is what
/// bounds the buffer and the work done per scan.
const PIECE: usize = 16 * 1024;

/// The automaton couldn't be built, for instance because the secrets are
/// enormous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskError;

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("couldn't prepare the output masker for these secrets")
    }
}

impl std::error::Error for MaskError {}

/// One secret and its KMP failure table, which finds the longest prefix of the
/// secret that a buffer ends with.
struct Secret {
    bytes: SecretValue,
    failure: Vec<usize>,
}

impl Secret {
    fn new(bytes: &[u8]) -> Secret {
        let mut failure: Vec<usize> = Vec::with_capacity(bytes.len());
        let mut k = 0usize;
        for (i, byte) in bytes.iter().enumerate() {
            if i == 0 {
                failure.push(0);
                continue;
            }
            while k > 0 && bytes.get(k) != Some(byte) {
                k = failure.get(k.saturating_sub(1)).copied().unwrap_or(0);
            }
            if bytes.get(k) == Some(byte) {
                k = k.saturating_add(1);
            }
            failure.push(k);
        }
        Secret {
            bytes: SecretValue::new(bytes),
            failure,
        }
    }

    /// The length of the longest proper prefix of this secret that `buf` ends
    /// with.
    fn pending_prefix(&self, buf: &[u8]) -> usize {
        let secret = self.bytes.expose();
        // A proper prefix is shorter than the secret, so it lies in the last
        // `len - 1` bytes, and KMP over just those bytes finds the longest.
        let window = secret.len().saturating_sub(1);
        let tail = buf
            .get(buf.len().saturating_sub(window)..)
            .unwrap_or_default();
        let mut k = 0usize;
        for byte in tail {
            while k > 0 && secret.get(k) != Some(byte) {
                k = self.failure.get(k.saturating_sub(1)).copied().unwrap_or(0);
            }
            if secret.get(k) == Some(byte) {
                k = k.saturating_add(1);
            }
        }
        k
    }
}

/// The masker for one output stream.
pub struct Masker {
    automaton: Option<AhoCorasick>,
    secrets: Vec<Secret>,
    /// Bytes not yet written: a possible start of a secret.
    held: Zeroizing<Vec<u8>>,
    /// How many of the first held bytes an earlier match already covered
    /// (D-045).
    carried: usize,
    /// Whether the last byte written was covered, so a run that continues is
    /// not given a second marker.
    in_run: bool,
    longest: usize,
}

impl Masker {
    /// A masker for these secrets. Empty secrets and repeats are dropped, since
    /// there is nothing to hide in an empty value (D-028). With no secrets
    /// left, the masker passes everything straight through.
    pub fn new<'a>(secrets: impl IntoIterator<Item = &'a [u8]>) -> Result<Masker, MaskError> {
        let distinct: BTreeSet<&[u8]> = secrets.into_iter().filter(|s| !s.is_empty()).collect();
        let longest = distinct.iter().map(|s| s.len()).max().unwrap_or(0);
        let automaton = if distinct.is_empty() {
            None
        } else {
            // The compact automaton: the full DFA could take tens of
            // megabytes for one 64 KiB secret.
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::Standard)
                    .kind(Some(AhoCorasickKind::ContiguousNFA))
                    .build(&distinct)
                    .map_err(|_| MaskError)?,
            )
        };
        let capacity = if longest == 0 {
            0
        } else {
            longest.saturating_add(PIECE)
        };
        Ok(Masker {
            automaton,
            secrets: distinct.iter().map(|s| Secret::new(s)).collect(),
            held: Zeroizing::new(Vec::with_capacity(capacity)),
            carried: 0,
            in_run: false,
            longest,
        })
    }

    /// How many bytes are being held back right now. Always fewer than the
    /// longest secret (NFR-10).
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Feeds one chunk of output, writing whatever is now final.
    pub fn push<W: Write>(&mut self, chunk: &[u8], out: &mut W) -> io::Result<()> {
        if self.automaton.is_none() {
            return out.write_all(chunk);
        }
        for piece in chunk.chunks(PIECE) {
            self.held.extend_from_slice(piece);
            self.settle(false, out)?;
        }
        Ok(())
    }

    /// Ends the stream: writes everything still held, then wipes it. The
    /// masker can be used again afterwards, as a fresh stream.
    pub fn finish<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        if self.automaton.is_none() {
            return Ok(());
        }
        let result = self.settle(true, out);
        self.held.zeroize();
        self.held.clear();
        self.carried = 0;
        self.in_run = false;
        result
    }

    /// Writes the bytes before `h` (all of them when `last`), and keeps the
    /// rest.
    fn settle<W: Write>(&mut self, last: bool, out: &mut W) -> io::Result<()> {
        let Some(automaton) = &self.automaton else {
            return Ok(());
        };
        let buf: &[u8] = &self.held;
        let runs = covered_runs(automaton, buf, self.carried);
        let h = if last {
            buf.len()
        } else {
            let pending = self
                .secrets
                .iter()
                .map(|s| s.pending_prefix(buf))
                .max()
                .unwrap_or(0);
            buf.len().saturating_sub(pending)
        };

        let mut written = 0usize;
        let mut in_run = self.in_run;
        let mut result = Ok(());
        for &(start, end) in &runs {
            if start >= h {
                break;
            }
            let end = end.min(h);
            if start > written {
                result = result
                    .and_then(|()| out.write_all(buf.get(written..start).unwrap_or_default()));
                in_run = false;
            }
            if !in_run {
                result = result.and_then(|()| out.write_all(MARKER));
            }
            in_run = true;
            written = end;
        }
        if written < h {
            result = result.and_then(|()| out.write_all(buf.get(written..h).unwrap_or_default()));
            in_run = false;
        }

        // A covered run that reaches past `h` carries into the held bytes.
        let carried = runs
            .iter()
            .find(|&&(start, end)| start <= h && end > h)
            .map_or(0, |&(_, end)| end.saturating_sub(h));

        // Drop the written bytes and wipe the stale copy left past the end.
        let old_len = self.held.len();
        let rest = old_len.saturating_sub(h);
        self.held.copy_within(h.., 0);
        if let Some(stale) = self.held.get_mut(rest..) {
            stale.zeroize();
        }
        self.held.truncate(rest);
        self.in_run = in_run;
        self.carried = carried;
        debug_assert!(self.held.len() < self.longest || last);
        result
    }
}

/// The maximal runs of covered bytes in `buf`, as sorted, disjoint
/// `(start, end)` pairs. The first `carried` bytes count as covered.
fn covered_runs(automaton: &AhoCorasick, buf: &[u8], carried: usize) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = automaton
        .find_overlapping_iter(buf)
        .map(|m| (m.start(), m.end()))
        .collect();
    if carried > 0 {
        spans.push((0, carried));
    }
    spans.sort_unstable();
    let mut runs: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match runs.last_mut() {
            // Touching spans form one run: no byte between them is uncovered.
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => runs.push((start, end)),
        }
    }
    runs
}

/// The one-shot reference for S7 (`docs/design.md` §2): masks a whole stream
/// at once, by trying every secret at every position. Slow and obviously
/// right, so the streaming masker has something independent to be compared
/// with. Not used by any command.
#[doc(hidden)]
pub fn reference_mask(secrets: &[&[u8]], input: &[u8]) -> Vec<u8> {
    let mut covered = vec![false; input.len()];
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        for start in 0..input.len() {
            let end = start.saturating_add(secret.len());
            if input.get(start..end) == Some(*secret) {
                if let Some(span) = covered.get_mut(start..end) {
                    span.fill(true);
                }
            }
        }
    }
    let mut out = Vec::with_capacity(input.len());
    let mut previous = false;
    for (byte, covered) in input.iter().zip(&covered) {
        if *covered {
            if !previous {
                out.extend_from_slice(MARKER);
            }
        } else {
            out.push(*byte);
        }
        previous = *covered;
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Runs a masker over `chunks` and returns its output.
    fn stream(secrets: &[&[u8]], chunks: &[&[u8]]) -> Vec<u8> {
        let mut masker = Masker::new(secrets.iter().copied()).unwrap();
        let mut out = Vec::new();
        for chunk in chunks {
            masker.push(chunk, &mut out).unwrap();
            let longest = secrets.iter().map(|s| s.len()).max().unwrap_or(0);
            assert!(
                masker.held() < longest.max(1),
                "held {} bytes",
                masker.held()
            );
        }
        masker.finish(&mut out).unwrap();
        assert_eq!(masker.held(), 0);
        out
    }

    fn one_chunk(secrets: &[&[u8]], input: &[u8]) -> Vec<u8> {
        stream(secrets, &[input])
    }

    fn marker_str() -> String {
        String::from_utf8(MARKER.to_vec()).unwrap()
    }

    #[test]
    fn the_marker_is_the_documented_text() {
        assert_eq!(MARKER, b"<concealed by vaultline>");
    }

    #[test]
    fn a_secret_is_replaced_by_the_marker() {
        let out = one_chunk(&[b"hunter2-secret"], b"my hunter2-secret is here");
        assert_eq!(out, format!("my {} is here", marker_str()).as_bytes());
    }

    #[test]
    fn output_with_no_secret_passes_through_unchanged() {
        let input = b"nothing to hide here\n\x00\xff binary too";
        assert_eq!(one_chunk(&[b"hunter2-secret"], input), input);
        assert_eq!(one_chunk(&[], input), input);
    }

    #[test]
    fn every_occurrence_is_replaced() {
        let out = one_chunk(&[b"abc"], b"abc-abc-abc");
        assert_eq!(out, format!("{m}-{m}-{m}", m = marker_str()).as_bytes());
    }

    #[test]
    fn a_secret_split_across_chunks_is_still_replaced() {
        let out = stream(&[b"hunter2-secret"], &[b"x hun", b"ter2-", b"secret y"]);
        assert_eq!(out, format!("x {} y", marker_str()).as_bytes());
    }

    #[test]
    fn a_secret_fed_one_byte_at_a_time_is_replaced() {
        let input = b"x hunter2-secret y hunter2-secret";
        let chunks: Vec<&[u8]> = input.chunks(1).collect();
        let out = stream(&[b"hunter2-secret"], &chunks);
        assert_eq!(out, one_chunk(&[b"hunter2-secret"], input));
        assert!(!contains(&out, b"hunter"));
    }

    #[test]
    fn a_false_start_is_released_once_it_cannot_match() {
        let out = stream(&[b"hunter2-secret"], &[b"hunt", b"ing party"]);
        assert_eq!(out, b"hunting party");
    }

    #[test]
    fn a_partial_secret_at_the_end_of_the_stream_is_released() {
        let out = stream(&[b"hunter2-secret"], &[b"ends with hunter2"]);
        assert_eq!(out, b"ends with hunter2");
    }

    #[test]
    fn overlapping_occurrences_of_one_secret_form_one_run() {
        // "aaaa" contains "aaa" at 0 and at 1: one run, one marker.
        let out = one_chunk(&[b"aaa"], b"xaaaay");
        assert_eq!(out, format!("x{}y", marker_str()).as_bytes());
    }

    #[test]
    fn overlapping_secrets_form_one_run() {
        let out = one_chunk(&[b"abcd", b"cdXYZ"], b"-abcdXYZ-");
        assert_eq!(out, format!("-{}-", marker_str()).as_bytes());
    }

    #[test]
    fn adjacent_occurrences_form_one_run() {
        let out = one_chunk(&[b"ab"], b"x ababab y");
        assert_eq!(out, format!("x {} y", marker_str()).as_bytes());
    }

    #[test]
    fn a_secret_inside_another_is_covered_by_the_longer_one() {
        let out = one_chunk(&[b"secret", b"my-secret-key"], b"[my-secret-key] [secret]");
        assert_eq!(out, format!("[{m}] [{m}]", m = marker_str()).as_bytes());
    }

    /// The case that D-045 amends the design for: `cd` is covered by `abcd`,
    /// but is held back because `cdXYZ` might follow.
    #[test]
    fn bytes_covered_by_an_earlier_match_are_not_released_as_text() {
        let secrets: [&[u8]; 2] = [b"abcd", b"cdXYZ"];
        let out = stream(&secrets, &[b"abcd", b"Q"]);
        assert_eq!(out, format!("{}Q", marker_str()).as_bytes());
        assert!(!contains(&out, b"cd"));
        // And when the longer secret does follow, it is still one run.
        let out = stream(&secrets, &[b"abcd", b"XYZ", b"!"]);
        assert_eq!(out, format!("{}!", marker_str()).as_bytes());
    }

    #[test]
    fn a_run_that_crosses_a_chunk_boundary_gets_one_marker() {
        let out = stream(&[b"abcd", b"cdXYZ"], &[b"ab", b"cd", b"XY", b"Z end"]);
        assert_eq!(out, format!("{} end", marker_str()).as_bytes());
    }

    #[test]
    fn empty_and_repeated_secrets_are_ignored() {
        let out = one_chunk(&[b"", b"abc", b"abc", b""], b"abc and abc");
        assert_eq!(out, format!("{m} and {m}", m = marker_str()).as_bytes());
        assert_eq!(one_chunk(&[b""], b"abc"), b"abc");
    }

    #[test]
    fn a_one_byte_secret_holds_nothing_back() {
        let mut masker = Masker::new([&b"x"[..]]).unwrap();
        let mut out = Vec::new();
        masker.push(b"axb", &mut out).unwrap();
        assert_eq!(masker.held(), 0);
        assert_eq!(out, format!("a{}b", marker_str()).as_bytes());
    }

    #[test]
    fn binary_output_is_handled_as_bytes() {
        let secret = [0x00u8, 0xff, 0x10, 0x80];
        let mut input = vec![1u8, 2, 3];
        input.extend_from_slice(&secret);
        input.push(9);
        let out = one_chunk(&[&secret], &input);
        let mut expected = vec![1u8, 2, 3];
        expected.extend_from_slice(MARKER);
        expected.push(9);
        assert_eq!(out, expected);
    }

    #[test]
    fn a_secret_that_is_part_of_the_marker_is_not_masked_inside_it() {
        // The marker itself is not input, so it is never scanned.
        let out = one_chunk(&[b"vaultline", b"abc"], b"abc");
        assert_eq!(out, MARKER);
    }

    #[test]
    fn the_masker_can_be_reused_after_finish() {
        let mut masker = Masker::new([&b"abcd"[..]]).unwrap();
        let mut first = Vec::new();
        masker.push(b"xab", &mut first).unwrap();
        masker.finish(&mut first).unwrap();
        assert_eq!(first, b"xab");
        let mut second = Vec::new();
        masker.push(b"cd", &mut second).unwrap();
        masker.finish(&mut second).unwrap();
        assert_eq!(second, b"cd", "the earlier bytes are not carried over");
    }

    #[test]
    fn a_write_error_is_returned_and_the_masker_stays_consistent() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut masker = Masker::new([&b"abc"[..]]).unwrap();
        let err = masker.push(b"hello abc", &mut Broken).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(masker.held() < 3);
    }

    #[test]
    fn a_long_secret_is_masked_across_many_pieces() {
        let secret: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
        let mut input = b"head ".to_vec();
        input.extend_from_slice(&secret);
        input.extend_from_slice(b" tail");
        let out = one_chunk(&[&secret], &input);
        assert_eq!(out, format!("head {} tail", marker_str()).as_bytes());
        let chunks: Vec<&[u8]> = input.chunks(997).collect();
        assert_eq!(stream(&[&secret], &chunks), out);
    }

    #[test]
    fn memory_stays_bounded_on_output_that_keeps_almost_matching() {
        // The output is an endless almost-secret: held bytes never reach the
        // secret's length.
        let secret = vec![b'a'; 5_000];
        let mut masker = Masker::new([secret.as_slice()]).unwrap();
        let mut out = Vec::new();
        for _ in 0..200 {
            masker.push(&[b'a'; 4_999], &mut out).unwrap();
            assert!(masker.held() < secret.len());
        }
        masker.finish(&mut out).unwrap();
    }

    #[test]
    fn the_pending_prefix_is_the_longest_proper_prefix_the_buffer_ends_with() {
        let secret = Secret::new(b"abcabd");
        assert_eq!(secret.pending_prefix(b"xxabcab"), 5);
        assert_eq!(secret.pending_prefix(b"xxabca"), 4);
        assert_eq!(secret.pending_prefix(b"xxab"), 2);
        assert_eq!(secret.pending_prefix(b"xx"), 0);
        assert_eq!(secret.pending_prefix(b""), 0);
        // A complete secret is not a proper prefix of itself.
        assert_eq!(secret.pending_prefix(b"abcabd"), 0);
        let repeating = Secret::new(b"aaaa");
        assert_eq!(repeating.pending_prefix(b"aaaaaaa"), 3);
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Cuts `input` at the (sorted, deduplicated) positions in `cuts`.
    fn cut<'a>(input: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
        let mut points: Vec<usize> = cuts.iter().map(|c| c % (input.len() + 1)).collect();
        points.push(0);
        points.push(input.len());
        points.sort_unstable();
        points.dedup();
        points.windows(2).map(|w| &input[w[0]..w[1]]).collect()
    }

    proptest! {
        /// S7 in miniature: streaming equals the one-shot reference under
        /// random chunking, with a small alphabet so that secrets overlap,
        /// repeat and contain each other.
        #[test]
        fn streaming_equals_the_one_shot_reference(
            secrets in proptest::collection::vec(proptest::collection::vec(0u8..3, 0..6), 0..4),
            input in proptest::collection::vec(0u8..3, 0..120),
            cuts in proptest::collection::vec(any::<usize>(), 0..20),
        ) {
            let refs: Vec<&[u8]> = secrets.iter().map(Vec::as_slice).collect();
            let expected = reference_mask(&refs, &input);
            let chunks = cut(&input, &cuts);
            prop_assert_eq!(stream(&refs, &chunks), expected);
        }
    }
}
