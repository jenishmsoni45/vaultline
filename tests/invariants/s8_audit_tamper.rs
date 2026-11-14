//! S8 (`docs/design.md` §2, §12.4): any edit, deletion, reordering or
//! truncation of audit entries is detected.
//!
//! For each case of §12.4, `audit verify` must fail. One case passes on
//! purpose: rolling back the log and the head together. A matching test then
//! shows that `verify --expect` with an anchor saved earlier catches it, so
//! together they document the known risk and how to close it.
//!
//! The checks run against the audit library, which is what `vaultline audit
//! verify` calls. `cli/audit.rs` runs a few of the same cases through the
//! binary.

use std::fs;
use std::path::PathBuf;

use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use vaultline::audit::{Anchor, Audit, HEAD_FILE, HEADER_LEN, LOG_FILE, RECORD_LEN, Verdict};
use vaultline::inject::reference::Reference;
use vaultline::secret::{Key, SecretValue};
use vaultline::session::{Origin, Session, open};
use vaultline::vault::Vault;

use crate::common::TestVault;

struct Fixture {
    tv: TestVault,
    vault: Vault,
    key: Key,
    log: Vec<u8>,
    head: Vec<u8>,
    /// The head after each append, oldest first: `heads[i]` covers `i + 1`
    /// records, and the last one is the current head.
    heads: Vec<Vec<u8>>,
}

fn reference(text: &str) -> Reference {
    Reference::parse(text.as_bytes()).expect("a reference")
}

impl Fixture {
    /// A vault whose log has `init`, `unlock`, and then a few records of every
    /// kind that touches an item.
    fn new() -> Fixture {
        let tv = TestVault::new("fake-passphrase-for-s8");
        // The head after `init` covers one record.
        let mut heads = vec![read(&tv, HEAD_FILE)];
        let vault = open(&tv.dir, &tv.passphrase(), Origin::Command).expect("unlock");
        heads.push(read(&tv, HEAD_FILE));
        {
            let session = Session::new(&vault);
            let value = SecretValue::new(b"fake-value-s8");
            for text in ["vault://p/one/a", "vault://p/two/a", "vault://p/three/a"] {
                session.set(&reference(text), &value).expect("set");
                heads.push(read(&tv, HEAD_FILE));
            }
            let wanted = [reference("vault://p/one/a")];
            session.resolve(&wanted.iter().collect()).expect("read");
            heads.push(read(&tv, HEAD_FILE));
            session.rm(&reference("vault://p/two/a")).expect("rm");
            heads.push(read(&tv, HEAD_FILE));
        }
        let key = vault.audit_key().expect("the audit key");
        let log = read(&tv, LOG_FILE);
        let head = read(&tv, HEAD_FILE);
        assert_eq!(
            log.len(),
            HEADER_LEN + 7 * RECORD_LEN,
            "init, unlock, 3 sets, a read and an rm are 7 records"
        );
        assert_eq!(heads.len(), 7);
        assert_eq!(heads.last(), Some(&head));
        Fixture {
            tv,
            vault,
            key,
            log,
            head,
            heads,
        }
    }

    fn records(&self) -> usize {
        (self.log.len() - HEADER_LEN) / RECORD_LEN
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tv.dir.join(name)
    }

    fn audit(&self) -> Audit<'_> {
        Audit::new(&self.tv.dir, self.vault.vault_id(), &self.key)
    }

    /// Puts these two files in place, whatever they hold.
    fn install(&self, log: &[u8], head: Option<&[u8]>) {
        fs::write(self.path(LOG_FILE), log).expect("write the log");
        match head {
            Some(head) => fs::write(self.path(HEAD_FILE), head).expect("write the head"),
            None => {
                let _ = fs::remove_file(self.path(HEAD_FILE));
            }
        }
    }

    fn restore(&self) {
        self.install(&self.log, Some(&self.head));
    }

    fn verify(&self) -> Verdict {
        self.audit().verify(None).expect("verify reads the files")
    }

    /// Installs a tampered log and head, and asserts that verify fails.
    fn assert_detected(&self, what: &str, log: &[u8], head: Option<&[u8]>) {
        self.install(log, head);
        let verdict = self.verify();
        assert!(
            !verdict.passed,
            "{what} was not detected: {}",
            verdict.report
        );
        self.restore();
    }
}

fn read(tv: &TestVault, name: &str) -> Vec<u8> {
    fs::read(tv.dir.join(name)).unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

/// The byte ranges of a record's fields (`vault-format.md` §5.2).
const FIELDS: [(&str, usize, usize); 7] = [
    ("seq", 0, 8),
    ("time", 8, 16),
    ("event", 16, 17),
    ("item_id", 17, 33),
    ("detail", 33, 41),
    ("prev_hash", 41, 73),
    ("mac", 73, 105),
];

fn record_start(index: usize) -> usize {
    HEADER_LEN + index * RECORD_LEN
}

#[test]
fn an_untouched_log_verifies() {
    let f = Fixture::new();
    let verdict = f.verify();
    assert!(verdict.passed, "{}", verdict.report);
    assert_eq!(f.heads.len(), f.records(), "one head per record");
}

#[test]
fn a_changed_byte_in_each_field_of_a_record_is_detected() {
    let f = Fixture::new();
    for index in [0, 1, f.records() / 2, f.records() - 1] {
        for (field, start, end) in FIELDS {
            for offset in [start, end - 1] {
                let mut log = f.log.clone();
                log[record_start(index) + offset] ^= 0x01;
                f.assert_detected(
                    &format!("a change in `{field}` of record {index}"),
                    &log,
                    Some(&f.head),
                );
            }
        }
    }
}

/// Stronger than the field by field case: every single byte of the log and of
/// the head, flipped in turn.
#[test]
fn every_single_byte_of_the_log_and_the_head_is_protected() {
    let f = Fixture::new();
    for at in 0..f.log.len() {
        let mut log = f.log.clone();
        log[at] ^= 0x80;
        f.assert_detected(&format!("a change at log byte {at}"), &log, Some(&f.head));
    }
    for at in 0..f.head.len() {
        let mut head = f.head.clone();
        head[at] ^= 0x80;
        f.assert_detected(&format!("a change at head byte {at}"), &f.log, Some(&head));
    }
}

#[test]
fn deleting_a_record_in_the_middle_is_detected() {
    let f = Fixture::new();
    for index in 0..f.records() {
        let mut log = f.log.clone();
        log.drain(record_start(index)..record_start(index) + RECORD_LEN);
        f.assert_detected(&format!("deleting record {index}"), &log, Some(&f.head));
    }
}

#[test]
fn swapping_two_records_is_detected() {
    let f = Fixture::new();
    for a in 0..f.records() {
        for b in a + 1..f.records() {
            let mut log = f.log.clone();
            for offset in 0..RECORD_LEN {
                log.swap(record_start(a) + offset, record_start(b) + offset);
            }
            f.assert_detected(
                &format!("swapping records {a} and {b}"),
                &log,
                Some(&f.head),
            );
        }
    }
}

/// Cutting 1 to k records off the end, without updating the head: the head
/// then covers records the log no longer has.
#[test]
fn cutting_records_off_the_end_without_updating_the_head_is_detected() {
    let f = Fixture::new();
    for cut in 1..=f.records() {
        let log = &f.log[..f.log.len() - cut * RECORD_LEN];
        f.assert_detected(&format!("cutting {cut} records"), log, Some(&f.head));
    }
}

#[test]
fn cutting_through_the_middle_of_a_record_is_detected() {
    let f = Fixture::new();
    for cut in 1..RECORD_LEN {
        let log = &f.log[..f.log.len() - cut];
        f.assert_detected(&format!("cutting {cut} bytes"), log, Some(&f.head));
    }
    // And a log cut inside its own header.
    for len in 0..HEADER_LEN {
        f.assert_detected(
            &format!("a log of {len} bytes"),
            &f.log[..len],
            Some(&f.head),
        );
    }
}

#[test]
fn appending_a_record_with_a_random_mac_is_detected() {
    let f = Fixture::new();
    let last = &f.log[f.log.len() - RECORD_LEN..];
    let prev_hash = vaultline_hash(last);
    let mut record = Vec::new();
    record.extend_from_slice(&(f.records() as u64).to_le_bytes());
    record.extend_from_slice(&0u64.to_le_bytes());
    record.push(6); // a `read`
    record.extend_from_slice(&[9u8; 16]);
    record.extend_from_slice(&0u64.to_le_bytes());
    record.extend_from_slice(&prev_hash);
    record.extend_from_slice(&[0x5a; 32]); // a MAC nobody computed
    assert_eq!(record.len(), RECORD_LEN);
    let mut log = f.log.clone();
    log.extend_from_slice(&record);
    f.assert_detected("a forged record, head unchanged", &log, Some(&f.head));
}

/// SHA-256 of a record, without a crypto crate of the test's own: the audit
/// library's own helper is the only one.
fn vaultline_hash(record: &[u8]) -> [u8; 32] {
    vaultline::vault::crypto::sha256(&[record])
}

#[test]
fn replacing_the_head_with_an_older_one_is_detected() {
    let f = Fixture::new();
    let n = f.records();
    for (i, old) in f.heads.iter().enumerate() {
        let covers = i + 1;
        f.install(&f.log, Some(old));
        let verdict = f.verify();
        if covers + 1 >= n {
            // The current head, or the one before it: the crash case, a record
            // written and the head not yet replaced (D-053).
            assert!(
                verdict.passed,
                "head covering {covers} of {n}: {}",
                verdict.report
            );
        } else {
            assert!(
                !verdict.passed,
                "an older head ({covers} of {n}) was not detected"
            );
        }
    }
    f.restore();
}

#[test]
fn deleting_the_head_is_detected() {
    let f = Fixture::new();
    f.assert_detected("deleting the head", &f.log, None);
    let verdict = {
        f.install(&f.log, None);
        let verdict = f.verify();
        f.restore();
        verdict
    };
    assert_eq!(verdict.report, "audit head missing");
}

#[test]
fn a_log_from_a_different_vault_is_detected() {
    let f = Fixture::new();
    let other = Fixture::new();
    // Same shape, other vault: its vault_id, key and chain differ.
    f.assert_detected("another vault's log", &other.log, Some(&f.head));
    f.assert_detected(
        "another vault's log and head",
        &other.log,
        Some(&other.head),
    );
    // The log of this vault with the head of the other one.
    f.assert_detected("another vault's head", &f.log, Some(&other.head));
}

/// The case that passes on purpose: the log and the head rolled back together
/// to an earlier, consistent state. Nothing inside the vault directory can
/// tell (D-015).
#[test]
fn rolling_back_the_log_and_the_head_together_passes() {
    let f = Fixture::new();
    for keep in 1..f.records() {
        f.install(&f.log[..record_start(keep)], Some(&f.heads[keep - 1]));
        let verdict = f.verify();
        assert!(
            verdict.passed,
            "a consistent rollback to {keep} records: {}",
            verdict.report
        );
    }
    f.restore();
}

/// ...and the anchor, saved earlier outside the vault directory, closes it.
#[test]
fn verify_expect_with_an_earlier_anchor_catches_the_rollback() {
    let f = Fixture::new();
    let anchor = f.audit().anchor().expect("the current anchor");
    assert_eq!(anchor.count as usize, f.records());
    // The log is intact: the anchor holds.
    assert!(f.audit().verify(Some(anchor)).unwrap().passed);

    // Roll back to 4 records, log and head together: plain verify passes...
    let keep = 4;
    f.install(&f.log[..record_start(keep)], Some(&f.heads[keep - 1]));
    assert!(f.verify().passed);
    // ...but the anchor from before the rollback is caught.
    let verdict = f.audit().verify(Some(anchor)).unwrap();
    assert!(!verdict.passed);
    assert!(verdict.report.contains("rolled back"), "{}", verdict.report);
    f.restore();
}

#[test]
fn an_anchor_from_an_edited_history_does_not_match() {
    let f = Fixture::new();
    // An anchor for the first three records, taken from the genuine log...
    let genuine = f.audit().anchor().expect("anchor");
    let at = Anchor {
        count: 3,
        hash: vaultline_hash(&f.log[record_start(2)..record_start(3)]),
    };
    assert!(f.audit().verify(Some(at)).unwrap().passed);
    // ...and one that names the wrong record at that position.
    let wrong = Anchor {
        count: 3,
        hash: vaultline_hash(&f.log[record_start(3)..record_start(4)]),
    };
    assert!(!f.audit().verify(Some(wrong)).unwrap().passed);
    assert!(f.audit().verify(Some(genuine)).unwrap().passed);
}

/// Random multi-byte edits, extensions and truncations of the log and the
/// head: any change at all is detected. One fixture serves every case.
#[test]
fn random_edits_are_detected() {
    let f = Fixture::new();
    let strategy = (
        proptest::collection::vec((any::<usize>(), 1u8..=255), 1..8),
        proptest::collection::vec(any::<u8>(), 0..300),
        0usize..400,
        any::<bool>(),
    );
    let mut runner = TestRunner::new(ProptestConfig::with_cases(500));
    runner
        .run(&strategy, |(edits, extension, truncate, in_head)| {
            let mut log = f.log.clone();
            let mut head = f.head.clone();
            for (at, xor) in &edits {
                let target = if in_head { &mut head } else { &mut log };
                let len = target.len();
                target[at % len] ^= xor;
            }
            log.extend_from_slice(&extension);
            log.truncate(log.len().saturating_sub(truncate));
            if log == f.log && head == f.head {
                return Ok(());
            }
            f.install(&log, Some(&head));
            let verdict = f.verify();
            prop_assert!(!verdict.passed, "undetected: {}", verdict.report);
            Ok(())
        })
        .unwrap();
    f.restore();
}
