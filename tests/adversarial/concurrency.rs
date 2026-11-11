//! P2-11, NFR-13: two concurrent writers take turns without losing each
//! other's changes, and a writer blocked for more than 10 seconds fails
//! cleanly with "another vaultline is writing".

use std::fs::OpenOptions;
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{Flock, FlockArg};
use vaultline::vault::{Error, Vault};

use crate::common::{TestVault, name, value};

#[test]
fn two_writers_take_turns_and_lose_nothing() {
    let v = TestVault::new("fake-passphrase-two-writers");
    let writers: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|who| {
            let dir = v.dir.clone();
            let passphrase = v.passphrase.clone();
            thread::spawn(move || {
                let vault = Vault::open(&dir, &crate::common::pass(&passphrase)).unwrap();
                for i in 0..6 {
                    let field = format!("{who}-{i}");
                    let val = format!("fake-{who}-value-{i}");
                    vault
                        .set(
                            &name("proj"),
                            &name("item"),
                            &name(&field),
                            &value(val.as_bytes()),
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    let fields: Vec<String> = v
        .vault
        .list(None)
        .unwrap()
        .iter()
        .map(|e| e.field.to_string())
        .collect();
    assert_eq!(fields.len(), 12, "every write survived: {fields:?}");
}

#[test]
fn a_writer_blocked_for_more_than_10_seconds_fails_cleanly() {
    let v = TestVault::new("fake-passphrase-blocked");
    v.set("proj", "item", "field", b"fake-blocked-value");
    let before = v.bytes();

    // Another writer holds the lock.
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(v.dir.join("lock"))
        .unwrap();
    let held = Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, e)| e)
        .unwrap();

    let start = Instant::now();
    let err = v
        .vault
        .set(
            &name("proj"),
            &name("item"),
            &name("field"),
            &value(b"fake-other-value"),
        )
        .expect_err("the write must give up");
    let waited = start.elapsed();
    assert!(matches!(err, Error::Busy), "{err}");
    assert_eq!(
        err.to_string(),
        "another vaultline is writing; try again in a moment"
    );
    assert!(
        waited >= Duration::from_secs(10),
        "gave up after {waited:?}"
    );
    assert!(waited < Duration::from_secs(15), "waited {waited:?}");
    assert_eq!(v.bytes(), before, "nothing was written");

    drop(held);
    v.set("proj", "item", "field", b"fake-after-value");
}
