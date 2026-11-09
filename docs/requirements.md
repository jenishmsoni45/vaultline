# Requirements

What vaultline must do, for whom, and how well. Each acceptance criterion is testable and names where its test lives. Details are in `design.md` (behaviour), `vault-format.md` (bytes), `threat-model.md` (security claims) and `decisions.md` (D-NNN).

## 1. Purpose

Developers keep API keys and passwords in plaintext `.env` files, which end up in repositories, backups, logs and screen shares. vaultline keeps them in an encrypted local vault instead. It injects them into a process's environment at run time, or renders them into a template on stdout, so plaintext never sits on disk. It is local-only and free, and uses no account.

## 2. Users

| ID | User | Needs |
|---|---|---|
| U1 | Application developer on a Mac | run local services (`npm start`, test suites) with secrets, without a plaintext `.env` |
| U2 | Developer who generates config | turn a config template into a working config for a tool, without saving the result to disk |
| U3 | Security-minded developer or reviewer | see what touched which secret, confirm the vault and log weren't tampered with, and understand what the tool does and doesn't protect |

## 3. User stories and acceptance criteria

Test paths are relative to `tests/`. "Fails" means exit code 1 with an error on stderr that names the problem, contains no secret value, and changes nothing.

### US-1 · As U1, I create a vault protected by a passphrase

| AC | Criterion | Test |
|---|---|---|
| 1 | `vaultline init` creates the vault directory (0700), containing `vault` (0600), plus `audit.log` and `audit.head` holding a single `init` record. | `cli/init.rs` |
| 2 | A passphrase shorter than 12 characters fails, and nothing is created. | `cli/init.rs` |
| 3 | `init` fails when a vault already exists, and leaves it untouched. | `cli/init.rs` |
| 4 | The new header holds the default Argon2id parameters: 262,144 KiB, t=3, p=4. | `cli/init.rs` |
| 5 | `VAULTLINE_DIR` chooses the directory; the default is `~/.vaultline`. | `cli/init.rs` |

### US-2 · As U1, I store, read, list and remove secrets

| AC | Criterion | Test |
|---|---|---|
| 1 | `set <ref>` reads the value from a hidden prompt, or from stdin when stdin isn't a terminal. One trailing `\n` is stripped unless `--raw` is given. A value given as an argument is a usage error. | `cli/set_get.rs` |
| 2 | With `--passphrase-stdin`, the first line of stdin is the passphrase and the rest is the value. | `cli/set_get.rs` |
| 3 | `get <ref>` writes exactly the stored bytes to stdout, with no newline added. | `cli/set_get.rs` |
| 4 | `get` fails before resolving anything when stdout is a regular file, and the file stays empty. | `cli/output_refusal.rs` |
| 5 | `list [project]` prints `project/item/field`, one per line, sorted, and never values. | `cli/list_rm.rs` |
| 6 | `rm <ref>` removes the field. Removing an item's last field removes the item. | `cli/list_rm.rs` |
| 7 | Names outside `A–Z a–z 0–9 . _ -`, or outside 1–64 bytes, fail. Values over 64 KiB fail. | `cli/set_get.rs`, unit tests in `inject/reference.rs` |
| 8 | Both `vault://p/i/f` and `p/i/f` are accepted on the command line. | `cli/set_get.rs` |

### US-3 · As U1, I run a command with secrets in its environment

| AC | Criterion | Test |
|---|---|---|
| 1 | Inherited variables whose whole value is a `vault://` reference are resolved for the child. Other variables pass through unchanged. | `cli/run.rs` |
| 2 | `--env-file F` adds `NAME=value` lines, and reference values are resolved. When a name is also inherited, the file wins, and stderr names the variable but never its value. | `cli/run.rs` |
| 3 | If any reference is malformed or can't be resolved, the child isn't started, and the error names the reference. | `cli/run.rs` |
| 4 | Every occurrence of every non-empty secret in the child's stdout and stderr becomes `<concealed by vaultline>`, wherever the chunk boundaries fall. | `invariants/s7_masking.rs` |
| 5 | Each secret shorter than 8 bytes triggers a warning on stderr that names its reference. | `cli/run.rs` |
| 6 | `run` exits with the child's code: 127 if the command isn't found, 126 if it isn't executable, and 128 + N if the child is killed by signal N. | `cli/run.rs` |
| 7 | SIGTERM and SIGHUP sent to `run` reach the child. SIGINT or SIGQUIT sent to the process group, as Ctrl-C does, reaches the child exactly once, because vaultline ignores them while the child runs (D-036). | `cli/run_signals.rs` |
| 8 | `--no-mask` passes output through unmasked and prints a warning. | `cli/run.rs` |
| 9 | No secret is written to any file (S6). | `invariants/s6_no_plaintext_on_disk.rs` |

### US-4 · As U2, I render a config template to stdout

| AC | Criterion | Test |
|---|---|---|
| 1 | `{{ vault://p/i/f }}` is replaced by the value, with whitespace inside the braces optional. Any other text, including other `{{ … }}`, is copied unchanged. | `cli/inject.rs`, unit tests in `inject/template.rs` |
| 2 | A malformed ref-tag fails with its line and column, and nothing is printed. | `cli/inject.rs` |
| 3 | A missing reference fails, and nothing is printed. | `cli/inject.rs` |
| 4 | With stdout redirected to a regular file, `inject` fails before resolving, and the file stays empty. | `cli/output_refusal.rs` |
| 5 | Without `-i`, the template is read from stdin. | `cli/inject.rs` |
| 6 | No secret is written to any file (S6). | `invariants/s6_no_plaintext_on_disk.rs` |

### US-5 · As U1, I unlock once and work without retyping

| AC | Criterion | Test |
|---|---|---|
| 1 | After `vaultline unlock`, `get`, `set`, `list`, `rm`, `run`, `inject` and `audit` work without asking for a passphrase. | `cli/agent.rs` |
| 2 | The agent wipes its key and exits after 15 idle minutes by default. `--idle-timeout` sets 1 second to 24 hours. | `invariants/s9_agent.rs` (using 2 s) |
| 3 | `vaultline lock` wipes the key, and later commands ask for the passphrase again. | `invariants/s9_agent.rs` |
| 4 | `vaultline agent stop` ends the agent and removes its socket. | `invariants/s9_agent.rs` |
| 5 | A connection from another UID is refused before any byte is read. The client refuses an agent owned by another UID. | `invariants/s9_agent.rs`, `adversarial/planted_socket.rs` |
| 6 | Ctrl-C in the terminal that ran `unlock` doesn't stop the agent. | `cli/agent.rs` |

### US-6 · As U1, I change my passphrase

| AC | Criterion | Test |
|---|---|---|
| 1 | `passwd` asks for the current passphrase even when an agent is unlocked. | `cli/passwd_rotate.rs` |
| 2 | Afterwards the old passphrase fails and the new one works, and the bytes of every item record are unchanged. | `cli/passwd_rotate.rs` |
| 3 | The new passphrase must be at least 12 characters. | `cli/passwd_rotate.rs` |
| 4 | The header ends up with the default Argon2id parameters and a new salt. | `cli/passwd_rotate.rs` |

### US-7 · As U3, I rotate every key

| AC | Criterion | Test |
|---|---|---|
| 1 | `rotate` creates a new master key and new item keys, and encrypts every payload again with fresh nonces. `vault_id` and every `item_id` are unchanged. | `cli/passwd_rotate.rs` |
| 2 | The old master key can't open the rotated vault. | unit tests in `vault/mod.rs` |
| 3 | `audit verify` still passes after `rotate`. | `cli/passwd_rotate.rs` |
| 4 | A running agent is locked by `rotate`. | `cli/agent.rs` |

### US-8 · As U3, I check what touched my secrets

| AC | Criterion | Test |
|---|---|---|
| 1 | The log records unlock, lock, idle timeout, the failed-unlock tally, each read (per item), set, rm, passwd, rotate and verify. Records carry item IDs only, never values or names. | `cli/audit.rs` |
| 2 | `audit verify` passes on an untouched log and fails on every tampering case in `design.md` §12.4. | `invariants/s8_audit_tamper.rs` |
| 3 | `audit head` prints `count:hash`, and `audit verify --expect` with an earlier anchor catches the log and head rolled back together. | `invariants/s8_audit_tamper.rs` |
| 4 | Failed unlocks are counted, and recorded at the next successful unlock. | `cli/audit.rs` |

### US-9 · As U3, I can rely on the vault file

| AC | Criterion | Test |
|---|---|---|
| 1 | Any change to the vault file gives a format or authentication error (S2). Slot swaps fail (S3). | `invariants/s2_tamper.rs`, `invariants/s3_swap.rs` |
| 2 | Every v1 fixture opens with its known contents (S5). | `invariants/s5_fixtures.rs` |
| 3 | A vault with an unknown format version fails with "unsupported format version N". | `adversarial/versions.rs` |
| 4 | The vault file contains no name and no value in plaintext. | `adversarial/no_plaintext_in_vault.rs` |

## 4. Non-functional requirements

Numbers here are chosen parameters and targets. Measured results are published only by scripts (D-006).

| ID | Requirement | How it is checked |
|---|---|---|
| NFR-1 | vaultline implements no cipher, KDF, MAC or random number generator. It uses only the crates in `design.md` §13. | review; `Cargo.toml` |
| NFR-2 | `#![forbid(unsafe_code)]` sits at every crate root. | `cli/scaffold.rs` |
| NFR-3 | No type that holds a secret implements Debug or Display. | `adversarial/secret_types.rs` (static assertions) |
| NFR-4 | Parser modules deny `unwrap`, `expect`, indexing, `panic` and unchecked arithmetic. | Clippy in CI |
| NFR-5 | No parser panics on any input (S10). | four fuzz targets; proptest no-panic tests |
| NFR-6 | vaultline never opens a network connection. | cargo-deny bans networking crates |
| NFR-7 | vaultline's processes have a core-dump limit of 0, and on Linux are non-dumpable. | `cli/hardening.rs` |
| NFR-8 | Target: unlocking with the default parameters takes 1 s or less on the developer Mac (D-001). | unlock bench and script (Phase 2) |
| NFR-9 | Target: with an unlocked agent, `run` adds 50 ms or less before the child starts (D-031). | `run` overhead bench and script (Phase 5) |
| NFR-10 | The masker holds back fewer bytes than the longest secret, whatever the output. | unit tests in `inject/mask.rs` |
| NFR-11 | Size limits: value up to 64 KiB, vault up to 64 MiB, agent frame up to 1 MiB, names 1–64 bytes, template and env file up to 16 MiB, Argon2id parameters up to the ceilings in `vault-format.md` §4.4 (D-027). | `adversarial/limits.rs` |
| NFR-12 | A crash or failure during a write never leaves a damaged or partly written vault. | `adversarial/atomic_write.rs` (injected faults) |
| NFR-13 | A second writer waits up to 10 s for the writer lock, then fails cleanly. | `adversarial/concurrency.rs` |
| NFR-14 | Platforms: macOS on Apple Silicon (day-to-day use, CI on PRs) and Linux x86_64 (CI on every push). Building on Windows fails with a clear `compile_error!` (D-021). | CI matrix |
| NFR-15 | Builds with Rust 1.86 (`rust-version`), with no `rust-toolchain.toml` (D-022). | CI pins 1.86 |
| NFR-16 | Developing locally needs nothing beyond the Rust already on the Mac. cargo-deny, cargo-audit and cargo-fuzz run in CI (D-020, D-022). | `make` targets print a skip message locally |
| NFR-17 | Tests leave nothing running and nothing outside their temporary directories (D-020). | agent guard in the test harness; idle-timeout exit |
| NFR-18 | CI: the Linux job runs on every push with a 60 s fuzz smoke per target. The macOS job runs on PRs. The campaign runs four targets for up to 6 h each, started by the owner (D-018, D-032). | workflow files |
| NFR-19 | Every number in `README.md` or `docs/` that describes a measurement comes from a script in the repo, and names it (D-006). | review; `scripts/` |
| NFR-20 | Every error says what failed and how to fix it, without secret values. | the stderr check in CLI tests |

## 5. Constraints

- Free and local only: no cloud services, paid APIs, accounts or credentials (`CLAUDE.md`).
- Nothing is installed on the developer Mac (D-020).
- Only well-known crates, pinned in `Cargo.lock`, each justified in the PR that adds it.
- No real secrets anywhere in the repo. Fixtures and tests use obviously fake values.

## 6. Non-goals

- Sharing secrets between people, syncing between machines, and any cloud backend.
- Touch ID, Keychain or any biometric unlock. No GUI.
- Windows.
- A pseudo-terminal for `run` (D-009); named pipes or `-o` output for `inject` (D-010).
- A passphrase environment variable (D-012), or a passphrase strength estimator (D-029).
- `mlock`ed memory (D-017). Padding items to hide sizes (D-005).
- Implementing any cipher, KDF, MAC or random number generator.
- Rotating the audit key (D-034), rotating the log by size, or rotating a single item's key.
- The 1Password shell-plugin side quest (D-023).
- `vaultline migrate`, until a v2 format exists (D-029).

## 7. Traceability

| Story | Invariants | Phase |
|---|---|---|
| US-1 | S4 | 2 (library), 3 (CLI) |
| US-2 | S1, S6 | 2, 3 |
| US-3 | S6, S7 | 3 |
| US-4 | S6 | 3 |
| US-5 | S9 | 4 |
| US-6 | S4 | 2, 3 |
| US-7 | S1, S8 | 2, 3, 4 |
| US-8 | S8 | 4 |
| US-9 | S2, S3, S5, S10 | 2 |
