//! What `vaultline run` adds before the child starts, with an unlocked agent
//! (D-031, D-059, NFR-9, P5-2).
//!
//! Two things are timed, each from the moment the process is spawned to the
//! moment it has exited:
//!
//! - `baseline-spawn`: `true` spawned directly;
//! - `run-through-agent`: `vaultline run -- true`, whose one `vault://`
//!   reference is resolved by the agent, with the audit records that appends.
//!
//! Their difference is the overhead: the socket round trip, the decryption,
//! the audit records and the child's setup, minus nothing that the baseline
//! doesn't also do. `scripts/bench-run-overhead.sh` runs this and prints the
//! difference; it is the only place an overhead figure comes from (D-006).
//!
//! Run it with `make bench`. It starts one agent in a temporary directory,
//! unlocks it once with the default Argon2id parameters (about a second), and
//! stops it again when the bench ends, even if the bench panics. As a backstop
//! the agent wipes its key and exits after five idle minutes, so nothing keeps
//! running afterwards. Every passphrase and value here is fake.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use vaultline::secret::{Passphrase, SecretValue};
use vaultline::vault::{KdfParams, Name, Vault};

const PASSPHRASE: &str = "fake-bench-passphrase-not-real";
const REFERENCE: &str = "vault://bench/db/password";

/// The built binary; cargo sets this for benches.
const VAULTLINE: &str = env!("CARGO_BIN_EXE_vaultline");

/// A command with an empty environment apart from what vaultline needs and
/// the one reference to resolve. Nothing here reads the user's own vault.
fn command(program: impl AsRef<std::ffi::OsStr>, dir: &Path, home: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("TMPDIR", home)
        .env("VAULTLINE_DIR", dir)
        .env("BENCH_SECRET", REFERENCE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Stops the agent when dropped, so a panic can't leave it running.
struct Agent {
    dir: PathBuf,
    home: PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = command(VAULTLINE, &self.dir, &self.home)
            .args(["agent", "stop"])
            .status();
        let socket = self.dir.join("agent.sock");
        let started = Instant::now();
        while socket.exists() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn run_overhead(c: &mut Criterion) {
    let tmp = tempfile::tempdir().expect("a temporary directory");
    let root = tmp.path().canonicalize().expect("the temporary directory");
    let home = root.join("home");
    std::fs::create_dir(&home).expect("a home directory");
    let dir = root.join("vaultline");

    let passphrase = Passphrase::new(PASSPHRASE.as_bytes());
    let vault = Vault::create(&dir, &passphrase, KdfParams::DEFAULT).expect("a new vault");
    vault
        .set(
            &Name::new("bench").expect("a name"),
            &Name::new("db").expect("a name"),
            &Name::new("password").expect("a name"),
            &SecretValue::new(b"fake-bench-value-not-real"),
        )
        .expect("set");
    drop(vault);

    // Unlock once. The guard is created first, so that even a failed unlock
    // that left an agent behind is stopped.
    let agent = Agent {
        dir: dir.clone(),
        home: home.clone(),
    };
    {
        use std::io::Write;
        let mut unlock = command(VAULTLINE, &dir, &home);
        unlock
            .args(["--passphrase-stdin", "unlock", "--idle-timeout", "5m"])
            .stdin(Stdio::piped());
        let mut child = unlock.spawn().expect("vaultline unlock");
        child
            .stdin
            .take()
            .expect("a pipe")
            .write_all(format!("{PASSPHRASE}\n").as_bytes())
            .expect("the passphrase");
        assert!(child.wait().expect("unlock").success(), "unlock failed");
    }

    let mut group = c.benchmark_group("run_overhead");
    group
        .sample_size(50)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    group.bench_function("baseline-spawn", |b| {
        b.iter(|| {
            let status = command("true", &dir, &home).status().expect("true");
            assert!(status.success());
        })
    });
    group.bench_function("run-through-agent", |b| {
        b.iter(|| {
            let status = command(VAULTLINE, &dir, &home)
                .args(["run", "--", "true"])
                .status()
                .expect("vaultline run");
            assert!(status.success(), "vaultline run failed");
        })
    });
    group.finish();
    drop(agent);
}

criterion_group!(benches, run_overhead);
criterion_main!(benches);
