# Phases

Phases 1–5, one PR each, started by the owner by name ("Start phase N"). For each phase: the goal, the scope, testable acceptance criteria, the tests to add, the docs to touch, what's out of scope, and where review should look hardest. The criteria are copied into the PR template and ticked off there, each one pointing to its code and its test. Decisions are cited as D-NNN.

## Rules for every phase

1. **Local checks:** `make lint` and `make test` pass on the Mac with Rust 1.86 and nothing installed (D-020, D-022).
2. **CI checks:** push the branch, and make sure the CI Linux job passes before opening the PR. That job covers cargo-deny, cargo-audit and the fuzz smoke run (D-022).
3. **Agents:** every test that starts an agent stops it. From Phase 4, CI checks that no `vaultline agent serve` process outlives the tests.
4. **Secrets in tests:** every CLI test checks that stderr contains none of its fake secret values.
5. **Format freeze:** once the Phase 2 PR is merged, the v1 format and fixtures are frozen (`vault-format.md` §6).
6. **When the design breaks:** if the design turns out wrong mid-phase, or a target is missed (NFR-8, NFR-9), stop and ask. The answer is recorded in `decisions.md`.
7. **New crates:** each new crate is justified in the PR and must build with Rust 1.86.

---

## Phase 1 · Scaffold (Jan 4)

**Goal:** a complete, empty skeleton with green CI.

**Scope**
- **Crate:** a `vaultline` package with a library and a binary, edition 2024, `rust-version = "1.86"`, `license = "MIT OR Apache-2.0"`, plus `LICENSE-MIT` and `LICENSE-APACHE` (D-019).
- **Crate roots:** `#![forbid(unsafe_code)]` in `src/lib.rs` and `src/main.rs`, and `#[cfg(not(unix))] compile_error!` (D-021).
- **Modules:** empty modules matching `architecture.md` §8.
- **Commands:** the full clap tree from `design.md` §4, including the hidden `agent serve`. Every command prints `not implemented yet` to stderr and exits 1.
- **`Makefile`:**
  - `test`;
  - `lint` (`cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`);
  - `audit` (`cargo deny check` and `cargo audit`);
  - `fuzz` (60 s per target with nightly);
  - `bench`.

  `audit` and `fuzz` print `SKIPPED: <tool> not installed; this check runs in CI` and exit 0 when the tool is missing, unless `CI=true` is set, in which case a missing tool is an error (D-022).
- **`deny.toml`:** deny known advisories; an allowlist of licenses; crates.io as the only source; networking crates banned (NFR-6).
- **Fuzzing:** a `fuzz/` crate outside the workspace, with one placeholder target, `smoke`, that proves the nightly and cargo-fuzz wiring in CI. Phase 2 removes it.
- **`.github/workflows/ci.yml`:**
  - a Linux job on every push: fmt, Clippy, tests, cargo-deny, cargo-audit, fuzz smoke;
  - a macOS job on pull requests only: fmt, Clippy, tests.

  Rust 1.86 is pinned for build and test, nightly is used only for fuzzing, actions are pinned by commit SHA, and permissions are `contents: read`.
- **`.gitignore`:** `target/`, `fuzz/target/`, `fuzz/artifacts/`.
- **`README.md`:** a one-paragraph stub that links to `docs/` and contains no numbers.

**Acceptance criteria**

| AC | Criterion |
|---|---|
| P1-1 | `make lint` and `make test` pass locally on Rust 1.86. |
| P1-2 | `#![forbid(unsafe_code)]` is at both crate roots. |
| P1-3 | Every command and option in `design.md` §4 exists. `vaultline <cmd> --help` exits 0. Running any command prints `not implemented yet` and exits 1. |
| P1-4 | Without the tools, `make audit` and `make fuzz` print SKIPPED and exit 0. With `CI=true`, a missing tool makes them fail. |
| P1-5 | `cargo deny check` passes in CI with the policy above. |
| P1-6 | CI runs the Linux job on push and the macOS job on PRs only, and both are green on the Phase 1 PR. |
| P1-7 | The fuzz crate is outside the workspace, and its `smoke` target runs for 60 s in CI. |
| P1-8 | The license files exist and the `license` field is set. |
| P1-9 | Every dependency in `Cargo.lock` comes from a direct dependency that the PR justifies. |

**Tests to add:** `tests/cli/scaffold.rs`, with `forbid_unsafe_at_crate_roots` and `every_command_is_stubbed`.

**Docs:** none, unless something here contradicts the design. In that case, stop and ask.

**Out of scope:** crypto, file I/O, any real command behaviour.

**Review focus:** the dependency list, CI triggers and pinning, the `deny.toml` policy.

---

## Phase 2 · Crypto core and vault format (Jan 5–10)

**Goal:** the vault library, implemented exactly as `vault-format.md` specifies, with S1–S5 proven and the v1 fixtures committed.

**Scope**
- **`src/secret.rs`:** secret types with no Debug or Display.
- **`vault/crypto.rs`:**
  - Argon2id with the `zeroize` feature and the parameter bounds;
  - HKDF subkeys;
  - XChaCha20-Poly1305 seal and open, with builders for the associated data;
  - the file MAC;
  - randomness from `OsRng` only.
- **`vault/format.rs`:** the v1 encoder and decoder (§4.1–4.4), the verification order (§4.7) and canonical writes (§4.8). The module denies `unwrap`, `expect`, indexing, `panic` and unchecked arithmetic.
- **`vault/mod.rs` (library API):**
  - `create` with given parameters, used by tests. The CLI's `init` will always use the defaults;
  - `open`, `get`, `set`, `rm`, `list`;
  - `passwd`, which re-wraps the master key;
  - `rotate`, which keeps the audit key (D-004, D-034).
- **`vault/store.rs` and `paths.rs`:**
  - `VAULTLINE_DIR`;
  - directory checks (not a symlink, owned by the user, mode 0700);
  - files at 0600;
  - atomic replace with flushes to disk;
  - the writer lock with a 10-second wait.
- **Fixtures:** `tests/fixtures/v1/{empty,basic,default-params}.vault` and their `README.md` (fake passphrases and contents), plus the generator that wrote them, which never runs again after this PR merges.
- **Bench:** `benches/unlock.rs` (criterion, small sample size) and `scripts/bench-unlock.sh`, which prints the measured unlock time for the default parameters. `make bench` runs it. It runs only when asked for and finishes in under a minute or two.
- **Fuzzing:** the `vault_file` target replaces `smoke` (D-035).

**Acceptance criteria**

| AC | Criterion |
|---|---|
| P2-1 | S1: proptest round trip for payloads and for whole vaults. |
| P2-2 | S2: every single-byte flip of `basic.vault` and every truncation gives a format or authentication error. Random multi-byte edits and extensions do too, and nothing panics. |
| P2-3 | S3, with the file MAC recomputed: payloads swapped between items, wrapped keys swapped, and records moved into a different vault all fail. Without recomputing: a record spliced in from another copy or an older snapshot of the same vault fails the file MAC. |
| P2-4 | S4: a wrong passphrase gives the single unlock error, and the message contains no passphrase. |
| P2-5 | S5: every fixture opens with the contents listed in its README. The README lists only fake values. |
| P2-6 | `passwd`: the old passphrase fails and the new one works. The bytes of every item record are identical, the salt is new, and the parameters are the defaults. |
| P2-7 | `rotate`: the master key, every item key and every nonce change. `vault_id`, every `item_id` and the audit key stay the same. The old master key can't open the result. |
| P2-8 | A header with parameters above the ceiling fails as a format error, and Argon2 never runs. `parse_header` is tested directly, and `open` returns at once. |
| P2-9 | Size limits: a file over 64 MiB is rejected before it is read. A value over 64 KiB is rejected. An `item_count` larger than the file can hold is rejected before anything is allocated. |
| P2-10 | A write that fails partway, through an injected I/O failure, leaves the old vault byte-for-byte intact. Temporary files never contain plaintext. Files are 0600 and the directory 0700. A bad directory is refused (wrong owner, group or world access, a symlink). |
| P2-11 | Two concurrent writers take turns. A writer blocked for more than 10 s fails cleanly. |
| P2-12 | Static assertions show that no secret type implements Debug or Display. |
| P2-13 | No name or value from the fixtures, or from proptest-generated vaults, appears in the vault bytes. |
| P2-14 | An unknown `format_version` gives "unsupported format version N". |
| P2-15 | `make bench` prints the measured unlock time. If it is over 1 s on the developer Mac, stop and raise it (D-001). |
| P2-16 | The `vault_file` fuzz target runs its 60 s CI smoke without a crash. |

US-9 AC1–4 (`requirements.md`) are covered by P2-2 and P2-3 (AC1), P2-5 (AC2), P2-14 (AC3) and P2-13 (AC4). NFR-12 and NFR-13 are covered by P2-10 and P2-11.

**Tests to add:**
- `tests/invariants/s1_roundtrip.rs`, `s2_tamper.rs`, `s3_swap.rs`, `s4_wrong_passphrase.rs`, `s5_fixtures.rs`;
- `tests/adversarial/no_plaintext_in_vault.rs`, `versions.rs`, `kdf_bounds.rs`, `limits.rs`, `atomic_write.rs`, `concurrency.rs`, `permissions.rs`, `secret_types.rs`;
- unit tests in `vault/`.

**Docs:** none expected. If any byte of `vault-format.md` turns out wrong, stop and ask before changing it.

**Out of scope:** the CLI (Phase 3) and the audit log (Phase 4). The wrapped audit key is in the format already (D-034).

**Review focus:** every line of crypto wiring; how nonces are generated; how associated data is built; the verification order; that the fixtures really are fake.

---

## Phase 3 · CLI, injection and masking (Jan 11–17)

**Goal:** every user-facing command working in-process, with S6 and S7 proven.

**Scope**
- **Commands:** `init`, `set`, `get`, `list`, `rm`, `passwd` and `rotate`, in-process only. The passphrase comes from `rpassword` or `--passphrase-stdin`, with the stdin rules from D-029.
- **Parsers:** `inject/reference.rs`, `inject/envfile.rs` and `inject/template.rs`, following the grammars in `design.md` §5.
- **`inject/mask.rs`:** the masker in `design.md` §6.
- **`inject/run.rs`:** building the environment and precedence, all-or-nothing resolution, pipes, signal handling following POSIX `system()` (D-036), exit codes, `--no-mask`, and the warnings (`design.md` §7).
- **`inject` command and `inject/output.rs`:** `inject`, and the regular-file refusal for `get` and `inject`.
- **`hardening.rs`:** applied at the start of every invocation.
- **Fuzzing:** the `reference` and `template` targets, plus a proptest no-panic test for the env-file parser.

**Acceptance criteria**

| AC | Criterion |
|---|---|
| P3-1 | US-1 AC2–5. AC1 without the audit files, which arrive in Phase 4. |
| P3-2 | US-2 AC1–8. |
| P3-3 | US-3 AC1–9. |
| P3-4 | US-4 AC1–6. |
| P3-5 | US-6 AC1–4. |
| P3-6 | US-7 AC1–2. |
| P3-7 | S6: the filesystem scan in `design.md` §12.3 finds no secret. |
| P3-8 | S7: streaming output equals the one-shot reference under random chunking, including overlapping secrets. An end-to-end run with a child that writes a secret across several writes shows only markers. |
| P3-9 | The masker never holds back as many bytes as the longest secret (NFR-10). |
| P3-10 | Hardening: `vaultline run -- sh -c 'ulimit -c'` prints 0 on macOS and Linux. On Linux, a child reading `/proc/$PPID/environ` is denied. |
| P3-11 | No secret appears in vaultline's arguments, and `set` has no value argument. |
| P3-12 | The `reference` and `template` fuzz targets run their 60 s CI smoke without a crash. The env-file parser passes its proptest no-panic test. |

**Tests to add:**
- `tests/cli/init.rs`, `set_get.rs`, `list_rm.rs`, `run.rs`, `run_signals.rs`, `inject.rs`, `output_refusal.rs`, `passwd_rotate.rs`, `hardening.rs`, `no_secret_in_argv.rs`;
- `tests/invariants/s6_no_plaintext_on_disk.rs`, `s7_masking.rs`;
- template and env-file size limits added to `tests/adversarial/limits.rs`;
- unit tests in `inject/`.

**Docs:** none expected.

**Out of scope:** the agent and the audit log.

**Review focus:** the masking buffer and its boundary flag; signal forwarding and double delivery; environment precedence; that no plaintext file appears anywhere; what error messages contain.

---

## Phase 4 · Agent and audit log (Jan 18–24)

**Goal:** the optional agent and the audit log, with S8 and S9 proven, and the fuzz-campaign workflow on `main`.

**Scope**
- **Agent:**
  - `agent/protocol.rs`, following `design.md` §8.1;
  - `agent/server.rs`: `agent.lock`, socket setup, peer check, the 5-second connection timeout, the idle timer, wiping on lock, timeout, stop and signals, and ignoring SIGHUP;
  - `agent/client.rs`, with its own peer check.
- **Commands:** `unlock` (spawning the agent and the stdin handshake), `lock` and `agent stop`. Every command routes through the agent per `architecture.md` §2, and `rotate` locks a running agent.
- **`audit.rs`:** the log, the head and the failed-unlock counter (`vault-format.md` §5), appending under the writer lock, verify with `--expect`, and the anchor.
- **Audit events:** every event in D-030 is logged from both the in-process path and the agent path. `init` creates the log and head.
- **Fuzzing:** the `agent_message` target, plus proptest no-panic tests for the log, head and counter parsers.
- **`.github/workflows/fuzz-campaign.yml`** (D-035):
  - triggered only by `workflow_dispatch`, with a duration input that defaults to the maximum;
  - one job per target (`vault_file`, `reference`, `template`, `agent_message`) with `timeout-minutes` of 360 or less;
  - corpus and crashes uploaded as artifacts;
  - a summary job that runs `scripts/fuzz-cpu-hours.sh`.
- **CI:** a step after the tests fails if any `vaultline agent serve` process is still running.

**Acceptance criteria**

| AC | Criterion |
|---|---|
| P4-1 | US-1 AC1: `init` creates the log and head with a single `init` record. |
| P4-2 | US-5 AC1–6. |
| P4-3 | US-7 AC3–4. |
| P4-4 | US-8 AC1–4. |
| P4-5 | S8: every case in `design.md` §12.4. |
| P4-6 | S9: every case in `design.md` §12.5. The root-refusal test runs in CI with `VAULTLINE_CI_SUDO=1`. |
| P4-7 | A socket owned by another UID is refused by the client before any byte is sent. |
| P4-8 | A stale socket is replaced only by the holder of `agent.lock`. A second agent can't start. A socket path that is too long gives a clear error. |
| P4-9 | The agent's arguments contain no passphrase. On Linux, the agent's core-dump limit is 0 and it is non-dumpable. |
| P4-10 | The `agent_message` fuzz target runs its 60 s CI smoke without a crash. The log, head and counter parsers pass their proptest no-panic tests. |
| P4-11 | `fuzz-campaign.yml` exists, triggers only on `workflow_dispatch`, and has one job per target with `timeout-minutes` of 360 or less. |
| P4-12 | No agent process remains after the test suite, locally or in CI. |

**Tests to add:**
- `tests/invariants/s8_audit_tamper.rs`, `s9_agent.rs`;
- `tests/cli/agent.rs`, `audit.rs`;
- `tests/adversarial/planted_socket.rs`;
- protocol and audit unit tests;
- additions to `cli/passwd_rotate.rs` (US-7 AC3), `cli/init.rs` (US-1 AC1), `cli/no_secret_in_argv.rs` and `cli/hardening.rs` (P4-9).

**Docs:** none expected.

**Out of scope:** benchmarks and README numbers.

**Review focus:** the peer check, in both directions; socket races (`agent.lock`, the stale socket, umask); how truncation is detected; where the master key lives and when it is wiped.

---

## Phase 5 · Harden and ship (Jan 25–31)

**Goal:** S10 holds after a real fuzz campaign, every published number comes from a script, and the project is ready to show.

**Before the phase starts:** the owner runs `gh workflow run fuzz-campaign.yml` on `main`, once or twice (D-018).

**Scope**
- **Campaign crashes:** triage every crash. Each fix comes with a regression test and its input added to the corpus.
- **Run overhead:** `benches/run_overhead.rs` and `scripts/bench-run-overhead.sh` (NFR-9).
- **Numbers:** `scripts/numbers.sh` runs or collects every number for the README: unlock time, `run` overhead, fuzz CPU-hours and crashes found and fixed (from the campaign artifacts), and test counts. Each number in the README names the script that produced it (D-006).
- **`README.md`:**
  - what vaultline is, building from source, usage for every command;
  - the security model, limited to claims C1–C13 from `threat-model.md` §7, each linked to its test;
  - limitations and the numbers;
  - how it was built with Claude Code under the owner's plan and review, and how it was verified (PLAN §9).
- **Threat model:** polish `threat-model.md`. Every claim is checked against its test, with changes approved by the owner.
- **New docs:**
  - `docs/postmortem.md`, on one real bug found during the build;
  - `docs/talk-outline.md`, for a 20-minute talk;
  - `docs/demo-script.md`, a shot-by-shot 3-minute demo of `run`, `inject`, masking and tamper detection, which the owner records (D-029).

**Acceptance criteria**

| AC | Criterion |
|---|---|
| P5-1 | Every crash from the campaign is fixed, with a regression test and a corpus entry. No campaign crash remains open (S10). |
| P5-2 | `make bench` shows `run` overhead with an unlocked agent of 50 ms or less on the developer Mac. If not, stop and raise it (D-031). |
| P5-3 | Every number in `README.md` and `docs/` that describes a measurement is produced by a script in `scripts/`, and names it. |
| P5-4 | The README's security section states only claims in `threat-model.md` §7, each linked to its test. |
| P5-5 | `postmortem.md`, `talk-outline.md` and `demo-script.md` exist. |
| P5-6 | S1–S9 are green in CI on Linux (push) and on macOS (PR). Fuzz smoke is green. |
| P5-7 | Every item in PLAN §9's definition of done is either done or listed in the PR, with its owner. Recording the video is the owner's. |

**Tests to add:** regression tests for every campaign crash, and the run-overhead bench.

**Docs:** `README.md`, `threat-model.md` (with approval), and the three new docs above.

**Out of scope:** new features. Anything new goes under Follow-ups.

**Review focus:** security claims against tests; that each number can be traced to a script; the README's limitations section.
