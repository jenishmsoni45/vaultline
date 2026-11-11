//! S2 (P2-2, D-002): any change to a vault file gives a format error or an
//! authentication error, never different plaintext and never a panic.
//!
//! The exhaustive tests run every flipped byte and every truncation of
//! `basic.vault` through the full open path in memory, Argon2id included,
//! spread over threads. A panic anywhere fails the test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use proptest::collection::vec;
use proptest::prelude::*;
use vaultline::secret::Passphrase;
use vaultline::vault::{Vault, decrypt_bytes};

use crate::common::{fixture_bytes, fixture_passphrase, install, is_format_or_auth};

const BASIC: &str = "basic.vault";

/// Runs `check` on every index in `0..count` across all CPUs and returns the
/// indexes where it failed.
fn par_failures(count: usize, check: impl Fn(usize) -> bool + Sync) -> Vec<usize> {
    let threads = thread::available_parallelism().map_or(4, |n| n.get());
    let next = AtomicUsize::new(0);
    let mut failures: Vec<usize> = thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut failed = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= count {
                            return failed;
                        }
                        if !check(i) {
                            failed.push(i);
                        }
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("a worker panicked"))
            .collect()
    });
    failures.sort_unstable();
    failures
}

/// Whether opening `bytes` fails with a format or authentication error.
fn rejected(bytes: &[u8], passphrase: &Passphrase) -> bool {
    match decrypt_bytes(bytes, passphrase) {
        Ok(_) => false,
        Err(e) => is_format_or_auth(&e),
    }
}

#[test]
fn the_untouched_fixture_opens() {
    let items = decrypt_bytes(&fixture_bytes(BASIC), &fixture_passphrase(BASIC)).unwrap();
    assert!(!items.is_empty());
}

#[test]
fn every_single_byte_flip_is_rejected() {
    let original = fixture_bytes(BASIC);
    let passphrase = fixture_passphrase(BASIC);
    let failures = par_failures(original.len(), |i| {
        let mut bytes = original.clone();
        bytes[i] ^= 0x01;
        rejected(&bytes, &passphrase)
    });
    assert!(
        failures.is_empty(),
        "flips accepted at offsets {failures:?}"
    );
}

#[test]
fn every_truncation_is_rejected() {
    let original = fixture_bytes(BASIC);
    let passphrase = fixture_passphrase(BASIC);
    let failures = par_failures(original.len(), |len| {
        rejected(&original[..len], &passphrase)
    });
    assert!(
        failures.is_empty(),
        "truncations accepted at lengths {failures:?}"
    );
}

#[test]
fn flips_through_the_file_path_are_rejected_too() {
    let original = fixture_bytes(BASIC);
    let passphrase = fixture_passphrase(BASIC);
    // One offset in each region: magic, version, vault_id, kdf_m_kib, salt,
    // mk_box, ak_box, item_count, the first record, a payload, the file MAC.
    let last = original.len() - 1;
    for offset in [0, 8, 12, 26, 40, 90, 160, 198, 205, 330, last] {
        let mut bytes = original.clone();
        bytes[offset] ^= 0x80;
        let (_tmp, dir) = install(&bytes);
        match Vault::open(&dir, &passphrase).and_then(|v| v.items()) {
            Ok(_) => panic!("a flip at offset {offset} was accepted"),
            Err(e) => assert!(is_format_or_auth(&e), "offset {offset}: {e}"),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn random_multi_byte_edits_are_rejected(
        edits in vec((any::<prop::sample::Index>(), 1u8..=255), 2..16),
    ) {
        let mut bytes = fixture_bytes(BASIC);
        let len = bytes.len();
        for (at, xor) in &edits {
            bytes[at.index(len)] ^= xor;
        }
        // Two edits at the same offset can cancel out; skip that case.
        prop_assume!(bytes != fixture_bytes(BASIC));
        prop_assert!(rejected(&bytes, &fixture_passphrase(BASIC)));
    }

    #[test]
    fn extensions_are_rejected(
        extra in vec(any::<u8>(), 1..256),
        at in any::<prop::sample::Index>(),
    ) {
        let original = fixture_bytes(BASIC);
        let passphrase = fixture_passphrase(BASIC);
        let mut appended = original.clone();
        appended.extend_from_slice(&extra);
        prop_assert!(rejected(&appended, &passphrase));
        let mut inserted = original.clone();
        let at = at.index(original.len());
        inserted.splice(at..at, extra.iter().copied());
        prop_assert!(rejected(&inserted, &passphrase));
    }
}
