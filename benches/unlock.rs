//! Unlock time with the default Argon2id parameters: 256 MiB, t=3, p=4
//! (D-001, NFR-8, P2-15).
//!
//! Run it with `make bench`, which calls `scripts/bench-unlock.sh` and prints
//! the measured time. One process, 256 MiB per unlock, ten samples of about
//! a second in all; nothing keeps running afterwards.

use std::time::Duration;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use vaultline::secret::Passphrase;
use vaultline::vault::{KdfParams, Vault};

fn unlock(c: &mut Criterion) {
    let tmp = tempfile::tempdir().expect("a temporary directory");
    let dir = tmp.path().join("vaultline");
    let passphrase = Passphrase::new(b"fake-bench-passphrase-not-real");
    Vault::create(&dir, &passphrase, KdfParams::DEFAULT).expect("a new vault");

    let mut group = c.benchmark_group("unlock");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    group.bench_function("default-params", |b| {
        b.iter(|| Vault::open(&dir, &passphrase).expect("unlock"))
    });
    group.finish();
}

criterion_group!(benches, unlock);
criterion_main!(benches);
