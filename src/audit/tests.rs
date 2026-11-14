//! Unit tests of the audit log. The tampering matrix of `design.md` §12.4 is
//! in `tests/invariants/s8_audit_tamper.rs`.

use super::*;
use crate::secret::Key;
use std::fs;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    tmp: tempfile::TempDir,
    key: Key,
    vault_id: [u8; ID_LEN],
}

impl Fixture {
    /// A private directory holding a fresh log and head.
    fn new() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = Key::random().unwrap();
        let vault_id = [7u8; ID_LEN];
        let fixture = Fixture { tmp, key, vault_id };
        let lock = lock(fixture.dir()).unwrap();
        fixture.audit().create(&lock).unwrap();
        fixture
    }

    fn dir(&self) -> &Path {
        self.tmp.path()
    }

    fn audit(&self) -> Audit<'_> {
        Audit::new(self.dir(), self.vault_id, &self.key)
    }

    fn log(&self) -> Vec<u8> {
        fs::read(self.dir().join(LOG_FILE)).unwrap()
    }

    fn head(&self) -> Vec<u8> {
        fs::read(self.dir().join(HEAD_FILE)).unwrap()
    }

    fn append(&self, entries: &[Entry]) -> Result<(), AuditError> {
        self.audit().append_locked(entries)
    }

    fn verdict(&self) -> Verdict {
        self.audit().verify(None).unwrap()
    }
}

fn read(i: u64) -> Entry {
    Entry::for_item(Event::Read, [i as u8; ID_LEN], 0)
}

#[test]
fn a_new_log_has_one_init_record_and_a_head_that_covers_it() {
    let f = Fixture::new();
    assert_eq!(f.log().len(), HEADER_LEN + RECORD_LEN);
    assert_eq!(f.head().len(), HEAD_LEN);
    let record = Record::decode(&f.log()[HEADER_LEN..]).unwrap();
    assert_eq!(
        (record.seq, record.event, record.detail),
        (0, Event::Init, 0)
    );
    assert_eq!(record.item_id, [0; ID_LEN]);
    let anchor = f.audit().anchor().unwrap();
    assert_eq!(anchor.count, 1);
    assert_eq!(anchor.hash, record.hash());
    assert!(f.verdict().passed, "{}", f.verdict().report);
}

#[test]
fn files_are_private_and_nothing_else_is_left_in_the_directory() {
    let f = Fixture::new();
    f.append(&[read(1)]).unwrap();
    let mut names: Vec<_> = fs::read_dir(f.dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, [HEAD_FILE, LOG_FILE, "lock"]);
    for name in [LOG_FILE, HEAD_FILE] {
        let mode = fs::metadata(f.dir().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[test]
fn appending_several_entries_keeps_the_chain_and_moves_the_head_with_each() {
    let f = Fixture::new();
    f.append(&[read(1), read(2), Entry::new(Event::Lock, LOCK_BY_STOP)])
        .unwrap();
    let log = f.log();
    assert_eq!(log.len(), HEADER_LEN + 4 * RECORD_LEN);
    let last = Record::decode(&log[HEADER_LEN + 3 * RECORD_LEN..]).unwrap();
    assert_eq!((last.seq, last.event, last.detail), (3, Event::Lock, 1));
    let anchor = f.audit().anchor().unwrap();
    assert_eq!((anchor.count, anchor.hash), (4, last.hash()));
    let verdict = f.verdict();
    assert!(verdict.passed, "{}", verdict.report);
    assert!(verdict.report.contains("4 records"), "{}", verdict.report);
}

#[test]
fn the_log_may_be_one_record_ahead_of_the_head_but_not_two() {
    let f = Fixture::new();
    let old_head = f.head();
    f.append(&[read(1)]).unwrap();
    // A crash between writing the record and replacing the head.
    fs::write(f.dir().join(HEAD_FILE), &old_head).unwrap();
    assert!(f.verdict().passed, "{}", f.verdict().report);
    f.audit().check().unwrap();
    // The next append starts from the log, and brings the head level.
    f.append(&[read(2)]).unwrap();
    assert!(f.verdict().passed);
    assert_eq!(f.audit().anchor().unwrap().count, 3);
    // Two behind is an older head (D-053).
    fs::write(f.dir().join(HEAD_FILE), &old_head).unwrap();
    let verdict = f.verdict();
    assert!(!verdict.passed);
    assert!(verdict.report.contains("older"), "{}", verdict.report);
    assert!(matches!(f.audit().check(), Err(AuditError::Damaged(_))));
}

#[test]
fn an_append_refuses_a_truncated_log_and_writes_nothing() {
    let f = Fixture::new();
    f.append(&[read(1), read(2)]).unwrap();
    let mut log = f.log();
    log.truncate(log.len() - RECORD_LEN);
    fs::write(f.dir().join(LOG_FILE), &log).unwrap();
    let head = f.head();
    let err = f.append(&[read(3)]).unwrap_err();
    assert!(matches!(err, AuditError::Damaged(_)), "{err}");
    assert!(err.to_string().contains("audit verify"), "{err}");
    assert_eq!(f.log(), log, "the log is untouched");
    assert_eq!(f.head(), head, "the head is untouched");
}

#[test]
fn an_append_refuses_a_log_cut_through_a_record() {
    let f = Fixture::new();
    let mut log = f.log();
    log.truncate(log.len() - 5);
    fs::write(f.dir().join(LOG_FILE), &log).unwrap();
    assert!(matches!(f.append(&[read(1)]), Err(AuditError::Damaged(_))));
    assert_eq!(f.log(), log);
}

#[test]
fn a_missing_log_or_head_is_reported_and_never_recreated() {
    let f = Fixture::new();
    fs::remove_file(f.dir().join(HEAD_FILE)).unwrap();
    assert!(matches!(
        f.append(&[read(1)]),
        Err(AuditError::Missing("audit head"))
    ));
    assert!(!f.dir().join(HEAD_FILE).exists());
    let verdict = f.verdict();
    assert!(!verdict.passed);
    assert_eq!(verdict.report, "audit head missing");

    let f = Fixture::new();
    fs::remove_file(f.dir().join(LOG_FILE)).unwrap();
    assert!(matches!(f.append(&[read(1)]), Err(AuditError::Missing(_))));
    assert!(!f.dir().join(LOG_FILE).exists());
    assert_eq!(f.verdict().report, "audit log missing");
}

#[test]
fn a_record_or_head_under_another_key_does_not_verify() {
    let f = Fixture::new();
    let other = Key::random().unwrap();
    let audit = Audit::new(f.dir(), f.vault_id, &other);
    assert!(!audit.verify(None).unwrap().passed);
    assert!(matches!(audit.check(), Err(AuditError::Damaged(_))));
}

#[test]
fn a_log_that_belongs_to_another_vault_is_refused() {
    let f = Fixture::new();
    let audit = Audit::new(f.dir(), [8u8; ID_LEN], &f.key);
    assert!(!audit.verify(None).unwrap().passed);
    assert!(matches!(audit.check(), Err(AuditError::Damaged(_))));
}

#[test]
fn verify_names_the_first_record_that_fails() {
    let f = Fixture::new();
    f.append(&[read(1), read(2)]).unwrap();
    let mut log = f.log();
    log[HEADER_LEN + RECORD_LEN + 20] ^= 1; // record 1, inside item_id
    fs::write(f.dir().join(LOG_FILE), &log).unwrap();
    let verdict = f.verdict();
    assert!(!verdict.passed);
    assert!(
        verdict.report.starts_with("record 1:"),
        "{}",
        verdict.report
    );
}

#[test]
fn verify_and_record_appends_the_result() {
    let f = Fixture::new();
    let verdict = f.audit().verify_and_record(None).unwrap();
    assert!(verdict.passed);
    let log = f.log();
    let last = Record::decode(&log[log.len() - RECORD_LEN..]).unwrap();
    assert_eq!((last.event, last.detail), (Event::Verify, 0));

    // A failing verification is recorded with detail 1 when the end of the log
    // can still be appended to. An edit far from the end is not what an append
    // looks at, so it gets through to `verify`, which reports it.
    f.append(&[read(1), read(2)]).unwrap();
    let mut log = f.log();
    log[HEADER_LEN + 20] ^= 1; // the first record's item_id: its MAC fails
    fs::write(f.dir().join(LOG_FILE), &log).unwrap();
    let verdict = f.audit().verify_and_record(None).unwrap();
    assert!(!verdict.passed);
    let log = f.log();
    let last = Record::decode(&log[log.len() - RECORD_LEN..]).unwrap();
    assert_eq!((last.event, last.detail), (Event::Verify, 1));
}

#[test]
fn verify_and_record_says_when_it_cannot_record() {
    let f = Fixture::new();
    let mut log = f.log();
    log.truncate(log.len() - 3);
    fs::write(f.dir().join(LOG_FILE), &log).unwrap();
    let verdict = f.audit().verify_and_record(None).unwrap();
    assert!(!verdict.passed);
    assert!(
        verdict.report.contains("no verify record was written"),
        "{}",
        verdict.report
    );
    assert_eq!(f.log(), log);
}

#[test]
fn an_anchor_round_trips_and_rejects_anything_else() {
    let f = Fixture::new();
    let anchor = f.audit().anchor().unwrap();
    let text = anchor.to_string();
    assert!(text.starts_with("1:") && text.len() == 2 + 64, "{text}");
    assert_eq!(Anchor::parse(&text).unwrap(), anchor);
    let zeros = "0".repeat(64);
    for bad in [
        "",
        ":",
        "1",
        "1:",
        &format!(":{zeros}"),
        &format!("x:{zeros}"),
        &format!("1:{}", "0".repeat(63)),
        &format!("1:{}", "A".repeat(64)),
        &format!("1:{}", "g".repeat(64)),
        &format!("-1:{zeros}"),
        &format!("1:{zeros}:1"),
        &format!("99999999999999999999999:{zeros}"),
        &format!(" 1:{zeros}"),
    ] {
        assert!(
            matches!(Anchor::parse(bad), Err(AuditError::BadAnchor)),
            "{bad:?}"
        );
    }
    assert!(Anchor::parse(&format!("0:{zeros}")).is_ok());
}

#[test]
fn an_anchor_taken_earlier_still_holds_after_the_log_grows() {
    let f = Fixture::new();
    f.append(&[read(1)]).unwrap();
    let anchor = f.audit().anchor().unwrap();
    f.append(&[read(2), read(3)]).unwrap();
    let verdict = f.audit().verify(Some(anchor)).unwrap();
    assert!(verdict.passed, "{}", verdict.report);
    assert!(verdict.report.contains(&anchor.to_string()));
    // The anchor of an empty log is the header's hash.
    let zero = Anchor {
        count: 0,
        hash: crypto::sha256(&[&f.log()[..HEADER_LEN]]),
    };
    assert!(f.audit().verify(Some(zero)).unwrap().passed);
    // A wrong hash, and an anchor from the future, fail.
    let wrong = Anchor {
        hash: [1; 32],
        ..anchor
    };
    assert!(!f.audit().verify(Some(wrong)).unwrap().passed);
    let future = Anchor {
        count: 99,
        ..anchor
    };
    assert!(!f.audit().verify(Some(future)).unwrap().passed);
}

#[test]
fn the_counter_counts_and_resets() {
    let f = Fixture::new();
    assert_eq!(read_counter(f.dir()), 0);
    note_failed_unlock(f.dir()).unwrap();
    note_failed_unlock(f.dir()).unwrap();
    assert_eq!(read_counter(f.dir()), 2);
    let mode = fs::metadata(f.dir().join(COUNTER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let lock = lock(f.dir()).unwrap();
    reset_counter(f.dir(), &lock).unwrap();
    assert_eq!(read_counter(f.dir()), 0);
}

#[test]
fn an_unreadable_counter_saturates_instead_of_restarting() {
    let f = Fixture::new();
    for bytes in [&b"short"[..], &[0u8; 9][..], &b""[..]] {
        fs::write(f.dir().join(COUNTER_FILE), bytes).unwrap();
        fs::set_permissions(
            f.dir().join(COUNTER_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(read_counter(f.dir()), COUNTER_UNREADABLE);
        note_failed_unlock(f.dir()).unwrap();
        assert_eq!(read_counter(f.dir()), COUNTER_UNREADABLE);
    }
}

#[test]
fn a_counter_that_is_not_ours_or_is_a_symlink_is_unreadable() {
    let f = Fixture::new();
    let path = f.dir().join(COUNTER_FILE);
    fs::write(&path, 3u64.to_le_bytes()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(read_counter(f.dir()), COUNTER_UNREADABLE);
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/dev/null", &path).unwrap();
    assert_eq!(read_counter(f.dir()), COUNTER_UNREADABLE);
}

#[test]
fn every_event_code_round_trips_and_other_codes_are_rejected() {
    for code in 1..=11u8 {
        assert_eq!(Event::from_code(code).unwrap().code(), code);
    }
    for code in [0u8, 12, 13, 255] {
        assert!(Event::from_code(code).is_none());
    }
}

#[test]
fn a_record_must_be_exactly_105_bytes() {
    let f = Fixture::new();
    let log = f.log();
    let record = &log[HEADER_LEN..];
    assert!(Record::decode(record).is_ok());
    assert!(Record::decode(&record[..RECORD_LEN - 1]).is_err());
    let mut long = record.to_vec();
    long.push(0);
    assert!(Record::decode(&long).is_err());
    assert!(Record::decode(&[]).is_err());
}
