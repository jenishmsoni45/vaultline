# vaultline

An encrypted local vault that injects secrets into child processes and templates without writing plaintext to disk.

- Secrets live in one encrypted file under `~/.vaultline`. Argon2id turns your passphrase into a key, which unlocks a master key, which unlocks a key for each item. Items use XChaCha20-Poly1305, and an HMAC covers the whole file.
- `vaultline run` puts secrets into a child's environment, and masks them if the child prints them. `vaultline inject` renders a template to standard output.
- An optional agent holds the unlocked key behind a Unix socket, so you type the passphrase once.
- Every use is written to a hash-chained, authenticated audit log.

It is a single-user tool for macOS and Linux. It was written to be read: the design, the threat model and every decision are in [`docs/`](docs/).

## Build from source

You need Rust 1.86 or newer and a Unix system (macOS or Linux; Windows is not supported).

```sh
cargo build --release --locked
./target/release/vaultline --help
```

The dependencies are pinned in `Cargo.lock`. Nothing else needs installing to build, test or use it: `make test` and `make lint` run on a stock Rust toolchain. `make audit` and `make fuzz` need `cargo-deny`, `cargo-audit` and `cargo-fuzz`; where those are missing they print `SKIPPED` and succeed, and CI runs them.

## Usage

References are written `vault://project/item/field`. On the command line, `get`, `set` and `rm` also accept `project/item/field`. Names use 1 to 64 letters, digits, `.`, `_` or `-`.

```sh
vaultline init                                   # asks for a passphrase of at least 12 characters, twice
vaultline set vault://shop/db/password           # reads the value from a hidden prompt, or from stdin
vaultline unlock                                 # starts the agent; it forgets the key after 15 idle minutes
DB_PASSWORD=vault://shop/db/password vaultline run -- ./deploy.sh
vaultline inject -i config.tpl | ./apply         # config.tpl holds {{ vault://shop/db/password }}
vaultline agent stop
```

| Command | What it does |
|---|---|
| `init` | Creates the vault directory (mode 0700) and an empty vault. Refuses if one exists. |
| `set <ref> [--raw]` | Reads a value from a hidden prompt, or from stdin when stdin isn't a terminal. Strips one trailing newline unless `--raw`. Never takes the value as an argument. |
| `get <ref>` | Writes the value to stdout, with no newline added. Refuses when stdout is a regular file. |
| `list [project]` | Prints `project/item/field` names, never values. |
| `rm <ref>` | Removes a field. Removing the last field of an item removes the item. |
| `passwd` | Changes the passphrase. |
| `rotate` | Replaces the master key and every item key, and tells a running agent to lock. |
| `run [--env-file FILE] [--no-mask] -- <cmd> [args]` | Resolves every `vault://` reference in the environment (and in the env file, whose values win), then runs the command. Output is masked unless `--no-mask`. Exits with the child's status. |
| `inject [-i FILE]` | Renders a template, from the file or stdin, to stdout, replacing `{{ vault://... }}`. Refuses when stdout is a regular file. |
| `unlock [--idle-timeout D]` | Starts the agent, or unlocks a locked one. `D` is `<n>s`, `<n>m` or `<n>h`. |
| `lock` | Wipes the agent's key and leaves the agent running. |
| `agent stop` | Wipes the key, removes the socket and exits. |
| `audit verify [--expect C:H]` | Checks the audit log's chain, MACs and head, and optionally an anchor. |
| `audit head` | Prints the current anchor, `<count>:<hash>`. |

Global option: `--passphrase-stdin` reads passphrases from stdin, one per line, instead of the terminal prompt. `VAULTLINE_DIR` chooses the vault directory (default `~/.vaultline`); it holds a path, never a secret. The agent's socket path has a length limit, so choose a short directory if `unlock` says the path is too long. Exit codes: 0 for success, 1 for a vaultline error, 2 for a usage error. The details are in [`docs/design.md`](docs/design.md) §4.

Pick a passphrase of several random words that you use nowhere else. A weak passphrase can still be guessed offline (R1 below).

## Security model

[`docs/threat-model.md`](docs/threat-model.md) says who vaultline defends against, what it doesn't defend against, and why. This README states only the claims in its section 7, each with the tests that prove it.

| # | Claim | Proven by |
|---|---|---|
| C1 | Without the passphrase, the vault file reveals no secret value and no name. | [`adversarial/no_plaintext_in_vault.rs`](tests/adversarial/no_plaintext_in_vault.rs), [S1](tests/invariants/s1_roundtrip.rs), [S5](tests/invariants/s5_fixtures.rs) |
| C2 | Changing any byte of the vault gives an error, never wrong data or a panic. | [S2](tests/invariants/s2_tamper.rs), [S10 (fuzz targets)](fuzz/fuzz_targets/) |
| C3 | Ciphertext moved between items, or into another vault, fails to open. Records spliced in from another copy or an older snapshot of the same vault are rejected by the file MAC. | [S3](tests/invariants/s3_swap.rs) |
| C4 | A wrong passphrase gives a clean error. | [S4](tests/invariants/s4_wrong_passphrase.rs) |
| C5 | Vaults written by format v1 always open. | [S5](tests/invariants/s5_fixtures.rs) |
| C6 | `run`, `inject`, `get` and `set` write no secret to disk. | [S6](tests/invariants/s6_no_plaintext_on_disk.rs) |
| C7 | `run` masks every occurrence of every secret in output, however it is chunked. | [S7](tests/invariants/s7_masking.rs) |
| C8 | Editing, deleting, reordering or truncating audit records is detected. Rolling back log and head together is caught given an anchor. | [S8](tests/invariants/s8_audit_tamper.rs) |
| C9 | Other UIDs can't use the agent, and the agent forgets the key on lock and idle timeout. | [S9](tests/invariants/s9_agent.rs) |
| C10 | No parser panics on any input. | [S10 (fuzz targets)](fuzz/fuzz_targets/) |
| C11 | vaultline's processes can't write core dumps, and on Linux are non-dumpable. | [`cli/hardening.rs`](tests/cli/hardening.rs) |
| C12 | Secrets never appear in vaultline's arguments, error messages or stderr. | [`cli/no_secret_in_argv.rs`](tests/cli/no_secret_in_argv.rs), [the stderr check in every CLI test](tests/common/cli.rs) |
| C13 | The directory and files are private to the user, and vaultline refuses to use them otherwise. | [`adversarial/permissions.rs`](tests/adversarial/permissions.rs) |

Several of the tests behind C11 and C13 need `sudo` or Linux, so they run only in CI.

## Limitations

What vaultline does not do, from [`docs/threat-model.md`](docs/threat-model.md) §5 and §8:

- **Malware running as you, root and physical access are out of scope** (T7, T8). Any process of yours can ask an unlocked agent for a secret, as with `ssh-agent`.
- **A weak passphrase can be guessed offline** (R1). Argon2id makes each guess costly, and the 12-character minimum blocks only the worst choices.
- **The file shows some metadata:** the vault ID, the Argon2id parameters, the item count, approximate item sizes and the modification time (R2).
- **Replacing the whole vault with an older valid copy can't be detected,** and neither can rolling the log and its head back together without a saved anchor (R3). `audit head` prints an anchor you can store elsewhere.
- **What a child does with a secret is up to the child.** Masking catches accidents in its stdout and stderr, not encoded forms, writes to `/dev/tty` or to files, or a secret split between stdout and stderr, and it is not a boundary against the child (R6, R7). Secrets shorter than 8 bytes produce a warning.
- **Copies that can't be wiped:** the environment block built for the child, the masker's own copy, kernel pipe buffers, the child's memory, terminal scrollback, swap and hibernation files (R6).
- **`vaultline inject | cat > file` writes the secret to a file.** The refusal guards against accidents, not intent (R8).
- **On macOS** the agent's memory is protected only by the OS's own rules; the non-dumpable setting exists only on Linux (R5).
- **Not built:** sharing, sync, cloud storage, Keychain, Touch ID and Windows.

## Numbers

Every measured number in this repository comes from a script in [`scripts/`](scripts/) and names it (D-006). `scripts/numbers.sh` runs or collects all of them. The chosen parameters are not results: the Argon2id defaults are 256 MiB, 3 passes and 4 lanes (D-001), the targets are an unlock in 1 s or less and a `run` overhead of 50 ms or less with an unlocked agent (D-001, D-031), and a campaign job fuzzes for at most 5 h 40 min (D-051).

| What | Result | Produced by |
|---|---|---|
| Unlock time, default Argon2id parameters, on the developer Mac | 302.08 ms (criterion's mean estimate) | `scripts/bench-unlock.sh` |
| Overhead of `run` with an unlocked agent, on the developer Mac | 17.42 ms (the run through the agent minus spawning the same child directly) | `scripts/bench-run-overhead.sh` |
| Fuzz campaign CPU-hours, from run 43640576661 of the `fuzz-campaign` workflow | 45.53 CPU-hours across 4 targets (measured run time times the cores the runner offered, so an upper bound) | `scripts/fuzz-cpu-hours.sh` |
| Fuzz crashes found by that run | 0 found, so 0 to fix; all 4 targets finished without a crash | `scripts/fuzz-crashes.sh` |
| Tests, on the developer Mac | 469 passed, 0 failed, 0 ignored (the tests that need `sudo` or Linux are skipped here and run in CI) | `scripts/count-tests.sh` |

## How it was built, and how it was verified

vaultline was written with Claude Code, working from a written plan and under the owner's review. The owner decided what to build and checked every phase; Claude Code wrote the code and the tests inside rules the owner set in a project file.

- **Plan first.** Phase 0 wrote no code. It settled the open questions one batch at a time, and recorded every question and answer in [`docs/decisions.md`](docs/decisions.md). The requirements, architecture, design, threat model and vault format came from those answers, and after Phase 0 the docs, not the code, are the source of truth.
- **One phase, one pull request.** There were five phases after the plan. The owner started each by name, a phase was built whole, with a test for every acceptance criterion in [`docs/phases.md`](docs/phases.md), and the owner reviewed and merged it. Anything the docs left open, or got wrong, stopped the work until the owner decided, and the decision was recorded.
- **Rules the tooling couldn't bend:** no hand-written ciphers, KDFs, MACs or random number generators (RustCrypto crates only); `#![forbid(unsafe_code)]`; secret types without `Debug` or `Display`; no `unwrap` or indexing on untrusted input; no real secrets anywhere, only fake values; fixtures that are known-answer tests and never regenerated.
- **Verification.** The ten invariants have a test each, in `tests/invariants/` and `fuzz/fuzz_targets/`. `make lint` and `make test` run locally. CI runs them on Linux for every push, with `cargo-deny`, `cargo-audit` and a short fuzz run, and on macOS for pull requests. A long fuzz campaign runs only in the `fuzz-campaign` workflow, which the owner starts by hand.
- **Mistakes are written down.** [`docs/postmortem.md`](docs/postmortem.md) covers a wrong claim about a dependency that survived a correction.

## More

[`docs/`](docs/) holds the requirements, architecture, design, threat model, vault format, decisions, phases, postmortem, a [talk outline](docs/talk-outline.md) and a [demo script](docs/demo-script.md).

vaultline is licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
