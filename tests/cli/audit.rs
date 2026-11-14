//! P4-2 (US-8 AC1, AC3, AC4) and the audit log's rules for commands
//! (`docs/design.md` §9, §11, D-030, D-047): what is recorded, what the
//! failed-unlock counter does, and what happens when the log can't be
//! appended to. The tampering matrix is `invariants/s8_audit_tamper.rs`.

use std::fs;

use vaultline::audit::{Event, HEADER_LEN, RECORD_LEN};

use crate::common::cli::Sandbox;
use crate::common::{contains, marker};

/// A vault with long, distinctive names, so that a name found in the log or the
/// head can't be a coincidence.
struct Names {
    project: String,
    item_a: String,
    item_b: String,
    field: String,
}

fn names() -> Names {
    Names {
        project: marker("project"),
        item_a: marker("item-a"),
        item_b: marker("item-b"),
        field: marker("field"),
    }
}

fn summary(sb: &Sandbox) -> Vec<(Event, [u8; 16], u64)> {
    sb.audit_records()
        .iter()
        .map(|r| (r.event, r.item_id, r.detail))
        .collect()
}

fn tail(sb: &Sandbox, n: usize) -> Vec<(Event, [u8; 16], u64)> {
    let all = summary(sb);
    all[all.len() - n..].to_vec()
}

const NONE: [u8; 16] = [0; 16];

/// US-8 AC1: the log records unlock, lock, idle timeout, the failed-unlock
/// tally, each read (per item), set, rm, passwd, rotate and verify. Records
/// carry item IDs only, never values or names. (Lock and idle timeout are in
/// `s9_agent.rs`, passwd and rotate in `passwd_rotate.rs`.)
#[test]
fn the_log_records_each_event_with_item_ids_and_nothing_else() {
    let sb = Sandbox::with_vault();
    let n = names();
    let ref_a = format!("{}/{}/{}", n.project, n.item_a, n.field);
    let ref_a2 = format!("{}/{}/{}-two", n.project, n.item_a, n.field);
    let ref_b = format!("{}/{}/{}", n.project, n.item_b, n.field);
    let value_a = sb.secret("value-a", &n.project, &n.item_a, &n.field);
    let value_b = marker("value-b");
    sb.register(&value_b);
    assert_eq!(summary(&sb).len(), 1, "only `init` so far");
    let id_a = sb.item_id(&n.project, &n.item_a);

    // set: unlock, then set, for an existing item.
    sb.run_pass(&["set", &ref_a2], value_b.as_bytes()).ok();
    assert_eq!(
        tail(&sb, 2),
        [(Event::Unlock, NONE, 0), (Event::Set, id_a, 0)]
    );
    // set creates the second item.
    sb.run_pass(&["set", &ref_b], value_b.as_bytes()).ok();
    let id_b = sb.item_id(&n.project, &n.item_b);
    assert_ne!(id_a, id_b);
    assert_eq!(tail(&sb, 1), [(Event::Set, id_b, 0)]);

    // get: one read, for the item that holds the field.
    sb.run_pass(&["get", &ref_a], b"").ok();
    assert_eq!(
        tail(&sb, 2),
        [(Event::Unlock, NONE, 0), (Event::Read, id_a, 0)]
    );

    // list returns no values, so it records the unlock and no read (D-037).
    let before = summary(&sb).len();
    sb.run_pass(&["list"], b"").ok();
    assert_eq!(summary(&sb).len(), before + 1);
    assert_eq!(tail(&sb, 1), [(Event::Unlock, NONE, 0)]);

    // run: one read per distinct item, whatever the number of references
    // (design §9). Three references, two items.
    let mut command = sb.command();
    command
        .env("ONE", format!("vault://{ref_a}"))
        .env("TWO", format!("vault://{ref_a2}"))
        .env("THREE", format!("vault://{ref_b}"))
        .args(["--passphrase-stdin", "run", "--", "true"]);
    let ran = sb.run_command(command, format!("{}\n", sb.passphrase).as_bytes());
    ran.ok();
    let records = tail(&sb, 3);
    assert_eq!(records[0], (Event::Unlock, NONE, 0));
    let mut reads: Vec<_> = records[1..].iter().map(|r| (r.0, r.2)).collect();
    assert_eq!(reads, [(Event::Read, 0), (Event::Read, 0)]);
    reads.clear();
    let mut ids: Vec<_> = records[1..].iter().map(|r| r.1).collect();
    ids.sort();
    let mut expected = vec![id_a, id_b];
    expected.sort();
    assert_eq!(ids, expected);

    // inject: a template that names the same item twice reads it once.
    let template = format!("a={{{{ vault://{ref_a} }}}} b={{{{ vault://{ref_a2} }}}}\n");
    sb.run_pass(&["inject"], template.as_bytes()).ok();
    assert_eq!(
        tail(&sb, 2),
        [(Event::Unlock, NONE, 0), (Event::Read, id_a, 0)]
    );

    // rm: 0 when a field goes and the item stays, 1 when the item goes too.
    sb.run_pass(&["rm", &ref_a2], b"").ok();
    assert_eq!(tail(&sb, 1), [(Event::Rm, id_a, 0)]);
    sb.run_pass(&["rm", &ref_b], b"").ok();
    assert_eq!(tail(&sb, 1), [(Event::Rm, id_b, 1)]);

    // verify: an unlock, then the result.
    let ran = sb.run_pass(&["audit", "verify"], b"");
    assert!(ran.ok().stdout_str().contains("audit log verified"));
    assert_eq!(
        tail(&sb, 2),
        [(Event::Unlock, NONE, 0), (Event::Verify, NONE, 0)]
    );

    // The log and the head hold no name, no value and no passphrase.
    for file in ["audit.log", "audit.head"] {
        let bytes = fs::read(sb.dir.join(file)).unwrap();
        for text in [
            &n.project,
            &n.item_a,
            &n.item_b,
            &n.field,
            &value_a,
            &value_b,
            &sb.passphrase,
        ] {
            assert!(!contains(&bytes, text.as_bytes()), "{file} holds {text}");
        }
    }
    // And the whole log verifies.
    let ran = sb.run_pass(&["audit", "verify"], b"");
    ran.ok();
}

/// US-8 AC4: failed unlocks are counted, and recorded at the next successful
/// unlock (`vault-format.md` §5.5).
#[test]
fn failed_unlocks_are_counted_and_recorded_at_the_next_good_unlock() {
    let sb = Sandbox::with_vault();
    sb.secret("v", "demo", "db", "password");
    let counter = sb.dir.join("unlock-failures");
    assert!(!counter.exists());
    let records_before = summary(&sb).len();

    for attempt in 1..=3u64 {
        sb.run(&["get", "demo/db/password"], b"not-the-passphrase\n")
            .fails_with("wrong passphrase");
        assert_eq!(fs::read(&counter).unwrap(), attempt.to_le_bytes());
    }
    assert_eq!(
        summary(&sb).len(),
        records_before,
        "a failed unlock writes no record: there is no key to MAC it with"
    );
    assert_eq!(fs::metadata(&counter).unwrap().len(), 8);

    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    assert_eq!(
        tail(&sb, 3),
        [
            (Event::Unlock, NONE, 0),
            (Event::FailedUnlocks, NONE, 3),
            (Event::Read, sb.item_id("demo", "db"), 0)
        ]
    );
    assert_eq!(fs::read(&counter).unwrap(), 0u64.to_le_bytes(), "reset");

    // The next good unlock has no tally to record.
    sb.run_pass(&["list"], b"").ok();
    assert_eq!(tail(&sb, 1), [(Event::Unlock, NONE, 0)]);
}

/// A wrong passphrase at `unlock` (the agent's own unlock) is counted too, and
/// the agent's later good unlock records it, with the agent as origin.
#[test]
fn the_agents_failed_unlocks_count_and_are_recorded_by_the_agent() {
    let sb = Sandbox::with_vault();
    sb.secret("v", "demo", "db", "password");
    sb.run(&["unlock"], b"not-the-passphrase\n")
        .fails_with("wrong passphrase");
    assert_eq!(
        fs::read(sb.dir.join("unlock-failures")).unwrap(),
        1u64.to_le_bytes()
    );
    sb.unlock(&[]).ok();
    assert_eq!(
        tail(&sb, 2),
        [(Event::Unlock, NONE, 1), (Event::FailedUnlocks, NONE, 1)]
    );
}

/// A counter that can't be read is recorded as such (`u64::MAX`), and reset.
#[test]
fn an_unreadable_counter_is_recorded_as_unreadable() {
    let sb = Sandbox::with_vault();
    fs::write(sb.dir.join("unlock-failures"), b"junk").unwrap();
    fs::set_permissions(
        sb.dir.join("unlock-failures"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    sb.run_pass(&["list"], b"").ok();
    assert_eq!(
        tail(&sb, 2),
        [
            (Event::Unlock, NONE, 0),
            (Event::FailedUnlocks, NONE, u64::MAX)
        ]
    );
}

fn cut_last_record(sb: &Sandbox) {
    let path = sb.dir.join("audit.log");
    let mut log = fs::read(&path).unwrap();
    log.truncate(log.len() - RECORD_LEN);
    fs::write(&path, log).unwrap();
}

/// D-047: a command that can't append stops before it reads a secret, starts a
/// child or changes the vault.
#[test]
fn a_truncated_log_stops_every_command_before_it_touches_a_secret() {
    let sb = Sandbox::with_vault();
    let secret = sb.secret("v", "demo", "db", "password");
    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    cut_last_record(&sb);
    let vault = sb.vault_bytes();
    let log = fs::read(sb.dir.join("audit.log")).unwrap();
    let head = fs::read(sb.dir.join("audit.head")).unwrap();

    for args in [
        &["get", "demo/db/password"][..],
        &["list"],
        &["rm", "demo/db/password"],
    ] {
        let ran = sb.run_pass(args, b"");
        ran.fails_with("audit verify");
        assert!(ran.stdout.is_empty(), "{args:?} printed something");
    }
    let ran = sb.run_pass(&["set", "demo/db/other"], b"fake-new-value");
    ran.fails_with("audit log is damaged");

    // run: the child is not started.
    let marker_file = sb.work.join("child-ran");
    let mut command = sb.command();
    command
        .env("DB", "vault://demo/db/password")
        .args(["--passphrase-stdin", "run", "--", "touch"])
        .arg(&marker_file);
    let ran = sb.run_command(command, format!("{}\n", sb.passphrase).as_bytes());
    ran.fails_with("audit verify");
    assert!(!marker_file.exists(), "the child ran");

    // inject prints nothing.
    let ran = sb.run_pass(&["inject"], b"x={{ vault://demo/db/password }}\n");
    ran.fails_with("audit verify");
    assert!(ran.stdout.is_empty());

    // Nothing changed: not the vault, not the log, not the head.
    assert_eq!(sb.vault_bytes(), vault);
    assert_eq!(fs::read(sb.dir.join("audit.log")).unwrap(), log);
    assert_eq!(fs::read(sb.dir.join("audit.head")).unwrap(), head);
    assert!(!contains(&log, secret.as_bytes()));
}

/// The inspecting commands still run on a damaged log, because reporting the
/// damage is their job. `audit verify` exits 1 and says what is wrong, and
/// skips its own record.
#[test]
fn verify_and_head_still_run_on_a_damaged_log() {
    let sb = Sandbox::with_vault();
    sb.secret("v", "demo", "db", "password");
    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    cut_last_record(&sb);
    let log = fs::read(sb.dir.join("audit.log")).unwrap();

    let ran = sb.run_pass(&["audit", "verify"], b"");
    ran.fails_with("audit verification failed");
    assert!(
        ran.stderr_str().contains("truncated"),
        "{}",
        ran.stderr_str()
    );
    assert!(ran.stdout.is_empty());
    assert_eq!(
        fs::read(sb.dir.join("audit.log")).unwrap(),
        log,
        "no verify record"
    );

    let ran = sb.run_pass(&["audit", "head"], b"");
    assert!(ran.ok().stdout_str().trim().contains(':'));
}

/// design §11: with the log missing, `audit verify` says "audit log missing"
/// and no other command recreates it.
#[test]
fn a_missing_log_is_reported_and_never_recreated() {
    let sb = Sandbox::with_vault();
    sb.secret("v", "demo", "db", "password");
    fs::remove_file(sb.dir.join("audit.log")).unwrap();

    let ran = sb.run_pass(&["audit", "verify"], b"");
    ran.fails_with("audit log missing");
    for args in [&["get", "demo/db/password"][..], &["list"]] {
        sb.run_pass(args, b"").fails_with("audit log is missing");
    }
    assert!(!sb.dir.join("audit.log").exists());

    // And the head.
    let sb = Sandbox::with_vault();
    fs::remove_file(sb.dir.join("audit.head")).unwrap();
    sb.run_pass(&["audit", "verify"], b"")
        .fails_with("audit head missing");
    sb.run_pass(&["list"], b"")
        .fails_with("audit head is missing");
    assert!(!sb.dir.join("audit.head").exists());
}

/// US-8 AC3: `audit head` prints `count:hash`, and `audit verify --expect`
/// with an earlier anchor catches the log and head rolled back together.
#[test]
fn audit_head_prints_an_anchor_and_expect_catches_a_rollback() {
    let sb = Sandbox::with_vault();
    sb.secret("v", "demo", "db", "password");
    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    // The state to roll back to: a consistent log and head.
    let log_then = fs::read(sb.dir.join("audit.log")).unwrap();
    let head_then = fs::read(sb.dir.join("audit.head")).unwrap();

    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    let ran = sb.run_pass(&["audit", "head"], b"");
    let anchor = ran.ok().stdout_str().trim().to_string();
    let (count, hash) = anchor.split_once(':').expect("count:hash");
    assert_eq!(count.parse::<usize>().unwrap(), summary(&sb).len());
    assert_eq!(hash.len(), 64);
    assert!(
        hash.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );

    // The anchor holds while the log only grows.
    sb.run_pass(&["get", "demo/db/password"], b"").ok();
    let ran = sb.run_pass(&["audit", "verify", "--expect", &anchor], b"");
    assert!(ran.ok().stdout_str().contains("still holds the anchor"));

    // Roll the log and the head back together. Nothing inside the directory
    // can tell: plain verify passes...
    fs::write(sb.dir.join("audit.log"), &log_then).unwrap();
    fs::write(sb.dir.join("audit.head"), &head_then).unwrap();
    let ran = sb.run_pass(&["audit", "verify"], b"");
    assert!(ran.ok().stdout_str().contains("audit log verified"));
    // ...but the anchor saved outside it catches the rollback.
    let ran = sb.run_pass(&["audit", "verify", "--expect", &anchor], b"");
    ran.fails_with("audit verification failed");
    assert!(
        ran.stderr_str().contains("rolled back"),
        "{}",
        ran.stderr_str()
    );
}

#[test]
fn a_tampered_log_fails_verify_through_the_binary() {
    let sb = Sandbox::with_vault();
    sb.secret("v", "demo", "db", "password");
    for _ in 0..3 {
        sb.run_pass(&["get", "demo/db/password"], b"").ok();
    }
    sb.run_pass(&["audit", "verify"], b"").ok();
    let path = sb.dir.join("audit.log");
    let mut log = fs::read(&path).unwrap();
    log[HEADER_LEN + RECORD_LEN + 20] ^= 1; // record 1, inside its item_id
    fs::write(&path, &log).unwrap();
    let ran = sb.run_pass(&["audit", "verify"], b"");
    ran.fails_with("audit verification failed");
    assert!(
        ran.stderr_str().contains("record 1"),
        "{}",
        ran.stderr_str()
    );
}

#[test]
fn a_mistyped_anchor_is_refused_before_the_passphrase_is_read() {
    let sb = Sandbox::with_vault();
    // No stdin at all: if the passphrase were asked for first, this would say
    // that standard input ended.
    sb.run(&["audit", "verify", "--expect", "7:abc"], b"")
        .fails_with("an anchor looks like COUNT:HASH");
}
