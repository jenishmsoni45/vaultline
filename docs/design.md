# Design

How vaultline behaves and why. This document covers the invariants and how each one is proven, command behaviour, grammars, masking, process and agent handling, failure modes, alternatives that were rejected, prior art and the test plan. Byte formats are in `vault-format.md`, diagrams in `architecture.md`, and the reasoning behind each choice is in `decisions.md` (cited as D-NNN).

## 1. Goals

1. Secrets live only in an encrypted local vault. They reach a process through its environment (`run`) or reach stdout (`get`, `inject`), and are never written to disk in plaintext.
2. The crypto is composed from audited RustCrypto crates, and every composition choice is written down and tested. vaultline implements no cipher, KDF, MAC or random number generator.
3. Every security claim in `threat-model.md` names a mechanism and a test.

## 2. Invariants

| # | Invariant | Mechanism | Proven by |
|---|---|---|---|
| S1 | Opening a sealed item returns exactly the original bytes. | AEAD seal and open; canonical payload encoding | `tests/invariants/s1_roundtrip.rs`: proptest over random payloads, names and field sets, both item-level and whole-vault encode, write, open |
| S2 | Any changed byte of a vault is rejected with a format or authentication error, never wrong plaintext or a panic (D-002). | AEAD tags, associated data, `file_mac`, bounded parser | `s2_tamper.rs`: every byte of `basic.vault` flipped in turn, every truncation length, proptest over random multi-byte edits and extensions. Also the `vault_file` fuzz target |
| S3 | An item's ciphertext moved into another item's slot fails to open. | `item_id` in the associated data of `ik_box` and `payload_box`; `file_mac` | `s3_swap.rs`. With the file MAC recomputed by a test-only re-MAC helper, so the AEAD layer is proven on its own: payloads swapped between items, wrapped keys swapped, and records moved into a different vault. Without recomputing: a record spliced in from another copy or an older snapshot of the same vault, which only `file_mac` catches because copies share `vault_id` (D-003) |
| S4 | A wrong passphrase gives a clean error. | `mk_box` AEAD failure mapped to a single unlock error | `s4_wrong_passphrase.rs`: the error kind and message are checked, and the message contains neither passphrase |
| S5 | v1 vaults open forever with their known plaintexts. | decoders kept per version (`vault-format.md` §6) | `s5_fixtures.rs` opens every file in `tests/fixtures/v1/` |
| S6 | `run` and `inject` never write a secret to the filesystem. | no plaintext file is ever created; stdout refused when it is a regular file; atomic-replace temporary files hold only ciphertext | `s6_no_plaintext_on_disk.rs` (see §12.3) |
| S7 | No byte of any secret occurrence reaches `run`'s captured output, whatever the read-chunk boundaries (unless `--no-mask`). | streaming masker (§6) | `s7_masking.rs`: proptest comparing streaming output with the one-shot reference under random chunking; integration test through a real child |
| S8 | Any edit, deletion, reordering or truncation of audit entries is detected. | SHA-256 chain, HMAC under the audit key, MAC'd head, optional anchor | `s8_audit_tamper.rs` (see §12.4) |
| S9 | The agent refuses other UIDs, and forgets the key after lock or idle timeout. | peer-UID check before any read; key wiped on lock, timeout, stop and signals | `s9_agent.rs`: unit tests of the peer decision, an integration test in CI where root is refused, a 2-second idle timeout, lock and stop |
| S10 | No parser panics on any input. | no `unwrap`, `expect`, indexing or unchecked arithmetic in parser modules, enforced by Clippy | four cargo-fuzz targets (`vault_file`, `reference`, `template`, `agent_message`), plus proptest no-panic tests for the env-file, audit-log, audit-head and failed-unlock-counter parsers |

What S7 means exactly: let U be every byte position in the child's output stream that lies inside an occurrence of any secret, overlapping occurrences included. Each maximal run of positions in U is replaced by one marker, `<concealed by vaultline>`, and every other byte passes through unchanged. A secret that happens to be a substring of the marker text can appear inside a marker. That isn't a leak, because no byte of the child's output survives inside a marker.

## 3. Cryptographic design

- **Envelope encryption** (D-003, D-004): passphrase, then KEK, then master key, then item keys. With this layering, `passwd` re-wraps 32 bytes instead of re-encrypting everything, and `rotate` revokes every old key at once. An item key exposed through one request doesn't open other items.
- **XChaCha20-Poly1305** with 24-byte random nonces. Random nonces are safe at this size, and no counter has to be kept in sync across processes and copies of a vault. AES-256-GCM's 12-byte nonce makes random nonces risky for a long-lived key, and would need nonce bookkeeping that a local file can't do reliably.
- **Argon2id** (RFC 9106) with 256 MiB, t=3, p=4 (D-001). The parameters are stored in the header, bounded by the parser, and upgraded by `passwd` and `rotate`.
- **Key separation**: the master key is used only as HKDF input. `K_wrap` and `K_mac` come from different HKDF `info` labels, and the audit key is a separate random key (D-034).
- **Associated data** binds every ciphertext to its role, the format version, the vault and the item (`vault-format.md` §4.5). The associated-data strings for different roles have different lengths, so they can never collide. The `item_id` stops slot swaps (S3). The `vault_id` keeps vaults apart if key material is ever shared between two vaults. Copies and snapshots of one vault share their `vault_id`, so splicing between them is caught by the file MAC, not by the associated data.
- **File MAC** (HMAC-SHA-256 under `K_mac`) covers every byte, so structural edits that AEAD alone can't see are caught: deleting, reordering or duplicating records, mixing records from older snapshots, and changing unencrypted fields.
- **Key commitment.** Poly1305-based AEADs are not key-committing. Partitioning-oracle attacks need an online oracle that tests many candidate keys. A local file has no such oracle, and an offline attacker can already test passphrase guesses directly against `mk_box`. Every ciphertext has exactly one legitimate key, which no attacker chooses. The design accepts this, and the threat model records it.
- **Verification order** (`vault-format.md` §4.7): bounds before the KDF, the master key before the MAC, the MAC before parsing the body. That keeps attacker-controlled bytes away from the body parser until they are authenticated. The body parser still assumes the bytes are hostile, for S10.

## 4. Commands

The binary is `vaultline` (D-024). References are written `vault://project/item/field`, and on the command line `get`, `set` and `rm` also accept the short form `project/item/field`.

| Command | Behaviour | Through an agent? |
|---|---|---|
| `init` | Creates the directory (0700) and an empty vault with fresh keys. Reads the passphrase twice, or once with `--passphrase-stdin`; it must be at least 12 characters (D-029). Refuses if a vault already exists. Appends `init`. | never |
| `set <ref>` | Reads the value from a hidden prompt, or from stdin when stdin isn't a terminal. Strips one trailing `\n` unless `--raw` is given. Never accepts the value as an argument (D-011). Creates the project, item or field as needed. With `--passphrase-stdin`, the first line of stdin is the passphrase and the rest is the value (D-029). | yes |
| `get <ref>` | Writes the value to stdout with no newline added. Refuses when stdout is a regular file (D-010, D-011). | yes |
| `list [project]` | Prints `project/item/field` names, one per line, sorted. Never prints values. | yes |
| `rm <ref>` | Removes a field. If it was the last field, the item goes too (D-028). | yes |
| `passwd` | Asks for the current passphrase, then the new one twice. Re-wraps the master key with a new salt and the default parameters (D-004). | never |
| `rotate` | Asks for the passphrase. Creates a new master key and new item keys, encrypts everything again, then tells a running agent to lock. | never |
| `run [--env-file F] [--no-mask] -- <cmd> [args]` | §7 | yes |
| `inject [-i F]` | Reads the template from F, or from stdin if F isn't given. Renders to stdout only, and refuses when stdout is a regular file (D-010). | yes |
| `unlock [--idle-timeout D]` | Starts the agent, or unlocks a running one that is locked. D is `<n>s`, `<n>m` or `<n>h`, from 1 second to 24 hours, and defaults to 15 minutes (D-013). | n/a |
| `lock` | Wipes the agent's key and leaves the agent running. | n/a |
| `agent stop` | Wipes the key, removes the socket, exits. | n/a |
| `audit verify [--expect C:H]` | `vault-format.md` §5.6 | yes |
| `audit head` | Prints the current anchor (D-015). | yes |
| `agent serve` | Hidden. The agent process itself, started by `unlock`. | n/a |

- **Global options:** `--passphrase-stdin`. The `VAULTLINE_DIR` environment variable chooses the directory; it holds a path, never a secret.
- **`--passphrase-stdin` input:** passphrases are read one per line, in the order the command asks for them. For `passwd`, that is the current passphrase, then the new one. Everything after the passphrase lines is the command's own input: the value for `set`, the template for `inject`, the child's stdin for `run`. Lines are read one byte at a time, so nothing beyond them is consumed (D-037).
- **Exit codes:**
  - 0 for success, 1 for any vaultline error, 2 for a usage error.
  - `run` exits with the child's code, 126 or 127 when the child can't be started, and 128 + N when the child is killed by signal N.

### 4.1 Resolving references (D-028)

- Every reference in a command is parsed and resolved before anything is written or spawned.
- If any reference fails to parse, names something that doesn't exist, or fails authentication, the command prints one error naming that reference and does nothing else. The value is never printed.
- Values that resolve to the empty string are injected but not masked, since there is nothing to hide.

## 5. Grammars

All three parsers work on bytes. None needs UTF-8 except where the grammar uses ASCII.

### 5.1 Reference

```
reference = "vault://" name "/" name "/" name
name      = 1*64( ALPHA / DIGIT / "." / "_" / "-" )   ; case-sensitive
```

### 5.2 Env file (`--env-file`)

```
file     = *( line LF ) [ line ]
line     = blank / comment / assign
blank    = *( SP / HTAB )
comment  = *( SP / HTAB ) "#" *( any byte except LF )
assign   = envname "=" value
envname  = ( ALPHA / "_" ) *( ALPHA / DIGIT / "_" )
value    = *( any byte except LF and CR )
```

- **Values are literal:** no quoting, no trimming, no `$VAR` expansion.
- **Reference values:** a value that starts with `vault://` must be a complete, valid reference, or the file is rejected. Any other value is passed through as a literal.
- **Rejected files:** a carriage return, a duplicate name, a malformed line, or a file larger than 16 MiB.

### 5.3 Template (`inject`, D-026)

```
ref-tag  = "{{" *( SP / HTAB ) reference *( SP / HTAB ) "}}"
```

How a template is scanned:

1. The scanner copies bytes until it finds `{{`.
2. If `{{` is followed, after optional spaces and tabs, by `vault://`, it starts a ref-tag. The tag must then be a valid reference followed by optional whitespace and `}}`. If it isn't, the template is rejected with the line and column of the `{{`.
3. Otherwise, one `{` is copied and scanning continues at the next byte. Other `{{ }}` syntax, such as Helm or Jinja, passes through unchanged.

There is no escape syntax. A template can't output the literal text `{{ vault://…}}`, and that limitation is documented. Templates larger than 16 MiB are rejected.

## 6. Masking (D-007, D-028)

1. **Secret set:** the distinct non-empty values resolved for this run. A warning on stderr names the reference of every value shorter than 8 bytes, because masking it can garble output. The warning shows the reference, never the value.
2. **One masker per stream:** stdout and stderr each get their own masker and their own thread. Each masker writes to the matching stream of vaultline.
3. **Matching:** a multi-pattern automaton (`aho-corasick`) finds every occurrence, overlapping ones included. After each chunk, the masker works out h, the start of the longest tail of its buffer that is a proper prefix of some secret.
4. **What can be decided:** every byte before h is final, because any occurrence that covers it has already completed. Bytes before h are written out, with each maximal covered run replaced by one marker. Bytes from h onwards are held.
5. **Runs that cross the boundary:** a flag remembers whether the last byte written was covered. A covered run that continues across h is then emitted as one marker, not two.
6. **End of stream:** the masker flushes with h equal to the buffer length.
7. **Memory:** the held tail is shorter than the longest secret, so memory stays bounded whatever the output.
8. **Output that isn't text:** output is handled as bytes and need not be UTF-8.

Known limits (D-007): encoded forms of a secret, output the child writes to `/dev/tty` or to files, and a secret split between stdout and stderr all get past the masker. Masking catches mistakes. It does not stop a child that sets out to leak.

## 7. `run` process handling (D-008, D-009, D-028)

1. **Building the environment:**
   1. Start from the inherited environment. Any variable whose entire value is a valid reference is replaced by the resolved value.
   2. A variable whose value starts with `vault://` but isn't a valid reference is an error.
   3. Assignments from the env file are applied next. The env file wins, and stderr names each inherited variable it overrides (the name only).
2. **Resolving:** every reference is resolved first, all or nothing (§4.1).
3. **Spawning:** stdin is inherited. stdout and stderr are pipes read by the maskers. With `--no-mask`, stdout and stderr are inherited too, and a warning is printed.
4. **Signals** (D-036), following POSIX `system()`:
   - While the child runs, vaultline ignores SIGINT and SIGQUIT. Ctrl-C reaches the child directly, exactly once, because the child shares the terminal's foreground process group.
   - SIGTERM and SIGHUP are forwarded to the child.
   - Known limits: `kill -INT` aimed at vaultline alone doesn't reach the child (send SIGTERM instead), and a SIGTERM or SIGHUP aimed at the whole group reaches the child twice.
5. **Exit:** vaultline waits for the child and for both maskers to flush, wipes the resolved values, and exits with the child's status (§4).
6. **Broken pipe:** if vaultline's own stdout reports a broken pipe, the masker closes the child's stdout pipe, so the child sees the broken pipe too.
7. **Core dumps for the child:** the child inherits a core-dump limit of 0 from the hardening in §10. That is intended, since the child holds secrets, and it is documented.

## 8. Agent (D-012, D-013, D-014)

- **Lifecycle:** see `architecture.md` §4. The agent is the same binary running `agent serve`. It reads the passphrase from its stdin pipe and holds `agent.lock` with `flock` for its whole life. A second agent can't start while that lock is held, which also settles any race over a stale socket.
- **Socket setup:**
  - The directory must not be a symlink, must be owned by the effective UID, and must not be accessible to group or others. This is checked with `lstat`.
  - The socket is bound with a temporary umask of 077.
  - A stale `agent.sock` is removed only by a process that holds `agent.lock`.
  - If the socket path is longer than the platform allows (`sun_path`), the agent stops with an error that suggests a shorter `VAULTLINE_DIR`.
- **Peer checks, both ways:**
  - The agent reads the caller's UID: `SO_PEERCRED` on Linux, `getpeereid` on macOS. A mismatch closes the connection before any byte is read.
  - The client checks the agent's UID the same way before sending anything, so a socket planted by another user can't collect a passphrase or a value.
- **Serving model:**
  - One thread, with `poll` on the listener and the idle timer. One request per connection.
  - A connection that sends nothing for 5 seconds is closed.
  - Only Resolve, Set, Remove, List, AuditVerify and AuditHead reset the idle timer. Status, Lock and Stop don't, so polling the agent never keeps it unlocked.
- **Idle timeout:** the agent wipes the key, appends `idle-timeout`, removes the socket and exits, so nothing lingers.
- **Lock:** wipes the key and appends `lock`. The agent stays up for a later `unlock`.
- **What the agent holds:** only the master key, wrapped in a zeroize-on-drop type. Subkeys and decrypted items exist only for the length of one request, and nothing decrypted is cached.
- **Fresh reads:** the agent re-reads and re-verifies the vault on every request, so writes from other processes are seen. If `file_mac` fails under its master key, for example after a `rotate` elsewhere, the agent locks itself and replies "locked".

### 8.1 Wire protocol, version 1

```
frame    = length:u32 body                          ; 1 <= length <= 1 MiB (D-027)
body     = proto_version:u8 (=1) kind:u8 fields
str      = len:u16 bytes                            ; references, project names
blob     = len:u32 bytes                            ; values, at most 64 KiB; passphrases
```

| Kind | Request | Fields | OK response |
|---|---|---|---|
| 1 | Resolve | count:u16, then count × str | count × blob, in request order |
| 2 | Set | str ref, blob value | empty |
| 3 | Remove | str ref | empty |
| 4 | List | u8 has_project, then str project if present | count:u32, then count × str |
| 5 | Unlock | blob passphrase | empty |
| 6 | Lock | none | empty |
| 7 | Stop | none | empty |
| 8 | Status | none | u8 unlocked, u32 seconds until idle timeout |
| 9 | AuditVerify | u8 has_expect, then str anchor if present | u8 passed, str report |
| 10 | AuditHead | none | str anchor |

- **Response layout:** `proto_version:u8` and `status:u8` (0 OK, 1 error). An error carries `code:u16` and a `str` message that never contains a secret.
- **Rejected frames:** any frame that is too long, has an unknown kind or version, has trailing bytes, or has a length that overruns the frame. The connection is then closed.
- **Wiping:** buffers that hold passphrases or values are wiped after use.
- **Fuzzing:** the `agent_message` fuzz target decodes arbitrary bytes as both requests and responses.

## 9. Audit log (D-015, D-016, D-030, D-034)

- **Formats** are in `vault-format.md` §5.
- **Who appends:** in-process commands and the agent append records while holding the writer lock. The record goes first, then the head is replaced.
- **When records are written:**
  - A successful unlock appends `unlock`, and also `failed-unlocks` if the counter is above 0 (§5.5).
  - A read appends one `read` per distinct item. Writes append `set`, `rm`, `passwd` or `rotate` after the vault has been replaced.
  - A failed write appends nothing.
- **`init`** creates the log, appends `init` and writes the head.
- **`audit verify`** holds the writer lock while it reads, checks everything in §5.6, and appends `verify` with the result. `list` returns no values, so it isn't logged as a read (D-037).
- **`audit head`** checks the head's MAC and prints `count:hash`. Saving that anchor elsewhere, and passing it to `verify --expect` later, catches a rollback of the log and head together.

## 10. Secret handling and process hardening (D-017, D-020)

- **At startup,** every invocation, the agent included:
  - sets `RLIMIT_CORE` to 0 (soft and hard);
  - on Linux, calls `prctl(PR_SET_DUMPABLE, 0)`.

  Both go through `nix` and affect only vaultline's own processes.
- **Secret types:** secrets are held in the wrapper types in `src/secret.rs`, which keep them in `secrecy` and `zeroize` types (`SecretBox`, `Zeroizing`) and wipe them on drop. Those library types do implement `Debug` (secrecy's prints `[REDACTED]`, and `Zeroizing<[u8; 32]>` prints the bytes), so they are only ever used inside the wrappers. The wrappers, and every type that holds one, implement neither Debug nor Display, and `static_assertions` checks that in tests (D-039).
- **Panics** unwind (the default), so wipe-on-drop still runs. No panic message formats a secret, and none can, since the types don't implement Debug or Display.
- **Parser modules** deny `clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `panic` and `arithmetic_side_effects`. The parser modules are `vault/format.rs`, `inject/{reference,envfile,template}.rs`, `agent/protocol.rs` and `audit.rs`.
- **Error messages** never contain values or passphrases. Every CLI test asserts that the fake secret values don't appear in stderr.
- **No logging:** there is no logging framework and no debug environment variable.
- **No secrets in arguments or the environment of our own processes:** the passphrase goes through a prompt, stdin, or the agent's stdin pipe.
- **Argon2:** `argon2` is built with its `zeroize` feature, so its working memory is wiped.
- **Copies vaultline doesn't control** are listed as residual risks in `threat-model.md` §8:
  - the environment block that `std::process::Command` builds for the child;
  - the masker automaton's copy of each secret;
  - kernel pipe buffers.

## 11. Failure modes

| Situation | Behaviour |
|---|---|
| Wrong passphrase | Unlock error. The failed-unlock counter goes up. Exit 1. |
| Any change to the vault file | Format or authentication error (S2). The file is never "repaired". |
| Vault file larger than 64 MiB or smaller than 234 bytes | Format error before the whole file is read. |
| Header asks for Argon2 parameters above the ceiling | Format error before the KDF runs. |
| Vault written by a newer version | "unsupported format version N". |
| Crash or full disk during a write | The old vault stays intact, because the rename never happened. A leftover `.vault.tmp-*` holds only ciphertext and is removed by the next writer that holds the lock. |
| Crash between appending an audit record and replacing the head | The log is one record ahead of the head, and `verify` passes (`vault-format.md` §5.6). |
| Two writers at once | The second waits for the writer lock for up to 10 seconds, then fails with "another vaultline is writing". |
| Directory owned by someone else, or group- or world-accessible | Refuse, and print the `chmod` or `chown` needed. |
| Agent crashes | The socket is stale. The next `unlock` takes `agent.lock` and replaces the socket. Commands fall back to in-process. |
| Socket owned by another UID | The client refuses before sending anything. |
| Socket path too long | Clear error that suggests a shorter `VAULTLINE_DIR`. |
| Reference not found | Error naming the reference. Nothing written or spawned. |
| Child can't be started | Exit 127 if not found, 126 if not executable. |
| Child killed by signal N | Exit 128 + N. |
| `inject` or `get` with stdout redirected to a file | Refused before anything is resolved. The file stays empty. |
| Audit log missing while the vault exists | `audit verify` fails with "audit log missing". Other commands recreate nothing. |
| System clock is wrong | Audit timestamps are wrong. They are informational, and ordering comes from `seq`. |
| Template or env file larger than 16 MiB | Rejected. |

## 12. Test plan

### 12.1 Layout

| Location | Contents |
|---|---|
| unit tests in each module | parser edge cases, KDF bounds, AEAD helpers, the peer-check decision, the masker state machine |
| `tests/invariants/` | one file per invariant, S1–S10 (§2) |
| `tests/adversarial/` | crafted inputs: tampered vaults, swapped records, hostile templates and env files, bad directory permissions, planted sockets, oversized frames |
| `tests/cli/` | end-to-end runs of the built binary (`CARGO_BIN_EXE_vaultline`) in temporary directories |
| `tests/fixtures/v1/` | known-answer vaults (`vault-format.md` §7) |
| `fuzz/fuzz_targets/` | `vault_file`, `reference`, `template`, `agent_message`. `vault_file` feeds arbitrary bytes straight to the header parser, the record parser and the payload decoder, skipping Argon2 so each input runs fast. The full open path, crypto included, is covered by S2 |
| `benches/` | criterion: unlock with the default parameters, `run` overhead through an agent |

### 12.2 Rules every test follows (D-020)

- **Temporary directories:** each test creates its own and points `VAULTLINE_DIR` (and `HOME` and `TMPDIR` where relevant) there. Nothing outside it is touched.
- **Cheap parameters:** end-to-end tests build their vaults through a library constructor that takes cheap Argon2 parameters, and the binary opens them like any other vault. Only one `init` test, the `default-params.vault` fixture, and one `passwd` test and one `rotate` test in each phase that tests them use 256 MiB, because `passwd` and `rotate` always write the default parameters. Those tests run one at a time (D-040).
- **No leftover agents:** every test that starts an agent holds a guard whose `Drop` stops it and waits for it to exit, so nothing keeps running after `cargo test`.
- **No secret leaks in test output:** fake secrets are random markers such as `fake-secret-<random>`, and every CLI test checks that stderr doesn't contain them.
- **No `sudo` on the Mac:** tests that need root to act as another UID run only when `VAULTLINE_CI_SUDO=1`, which only CI sets.

### 12.3 S6: nothing written in plaintext

1. Point `HOME`, `TMPDIR` and `VAULTLINE_DIR` at fresh temporary directories, and use a temporary working directory.
2. Run, both through an agent and in-process:
   - `run` with a child that prints its secret to stdout;
   - `inject` into a pipe;
   - `get` into a pipe;
   - `set` and `rotate`.
3. Walk every file under those directories and assert that no secret marker appears in any of them, raw or hex-encoded.
4. Also assert that `inject > file` and `get > file` are refused and leave the file empty.

The test checks every place vaultline could write. It can't prove anything about the rest of the disk, so the design guarantees by construction that vaultline only writes inside `VAULTLINE_DIR` (`architecture.md` §7).

### 12.4 S8: audit tampering

For each case below, `audit verify` must fail:

- change one byte in each field of a record;
- delete a record in the middle;
- swap two records;
- cut 1 to k records off the end, without updating the head;
- cut through the middle of a record;
- append a record with a random MAC;
- replace the head with an older one;
- delete the head;
- copy in a log that belongs to a different vault.

One case passes on purpose: rolling back the log and the head together. A matching test then shows that `verify --expect` with an anchor saved earlier catches it. Together these document the known risk and how to close it.

### 12.5 S9: the agent

- **Peer decision:** unit tests with injected UIDs.
- **Another UID:** in CI only (`VAULTLINE_CI_SUDO=1`), an agent runs as the CI user, root connects through `sudo`, and the agent refuses before reading anything. Root is another UID, and root can get past the directory permissions, so this exercises the peer check itself.
- **Idle timeout:** with `--idle-timeout 2s`, after the timeout the socket is gone, the process has exited, and an `idle-timeout` record exists.
- **Lock:** after `lock`, Status reports locked, Resolve fails, and a `lock` record exists.
- **Stop:** after `agent stop`, the process has exited and the socket is gone.
- **Wiping:** the key holder is a zeroize-on-drop type, proven with static assertions. The tests prove that the agent can no longer decrypt. Inspecting freed memory would need unsafe code, so the actual scrubbing is trusted to `zeroize`.

### 12.6 CI (D-018, D-021, D-022, D-032)

| Job | Trigger | Steps |
|---|---|---|
| Linux (ubuntu, Rust 1.86) | every push | fmt check, Clippy with `-D warnings`, tests including the sudo tests, cargo-deny, cargo-audit, then nightly cargo-fuzz smoke: 60 s per existing target |
| macOS (Apple Silicon, Rust 1.86) | pull requests | fmt check, Clippy, tests including the sudo tests |
| fuzz campaign | started by the owner (`workflow_dispatch`) | one job per target, up to 6 hours each; corpus and crashes uploaded as artifacts; a script sums CPU-hours |

Actions are pinned by commit SHA, and workflow permissions are `contents: read`.

## 13. Dependencies

Every crate is well known and pinned in `Cargo.lock`, and each one is justified in the PR that adds it. All must build with Rust 1.86.

| Crate | Purpose |
|---|---|
| `argon2` (with `zeroize`) | KEK derivation |
| `chacha20poly1305` | XChaCha20-Poly1305 |
| `hkdf`, `hmac`, `sha2` | subkeys, file MAC, audit MACs, chain |
| `getrandom` | OS CSPRNG: keys, salts, nonces, IDs (D-038) |
| `zeroize`, `secrecy` | secret types |
| `clap` | command line |
| `nix` | peer credentials, `flock`, `poll`, `setrlimit`, `prctl`, `fstat`, `kill`, umask |
| `aho-corasick` | masking automaton |
| `rpassword` | hidden passphrase prompt |
| `signal-hook` | signal handling: forwarding in `run`, wiping on signals in the agent |
| dev: `proptest`, `criterion`, `tempfile`, `static_assertions` | tests and benches |
| fuzz: `libfuzzer-sys` | fuzz harnesses |

`serde` appears in PLAN's stack but isn't needed. Both binary formats and the wire protocol are hand-specified, so that every byte is defined and so that secret values aren't copied into buffers that are never wiped. No async runtime is used, since one thread with `poll` is enough. `cargo-deny` bans networking crates, because vaultline never touches the network.

## 14. Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| A single key, no envelope | `passwd` would re-encrypt everything, and there'd be no clean way to revoke keys or limit what one key exposes |
| AES-256-GCM, or ChaCha20-Poly1305 with a 12-byte nonce | random nonces aren't safe for a long-lived key; counters would need shared state |
| PBKDF2, scrypt | Argon2id won the Password Hashing Competition and is specified in RFC 9106, and it resists GPU attacks better than PBKDF2 |
| JSON with base64; bincode or CBOR (D-002) | awkward to authenticate; bincode's format depends on the crate version |
| Names in plaintext (D-005) | leaks what is worth attacking |
| A PTY for `run` (D-009) | needs unsafe `pre_exec` or another crate, and merges stdout and stderr |
| `inject -o`, named pipes (D-010) | more code and a race, for little gain over `>(...)` |
| A passphrase environment variable (D-012) | inherited by children, readable by processes running as the same user |
| Agent hands out item keys (D-014) | keys would end up in many processes |
| Audit key derived from the master key (D-034) | `rotate` would make old entries impossible to verify |
| Unkeyed hash chain (D-016) | anyone with disk access can rewrite the whole chain |
| `mlock` (D-017) | locked-memory limits; Argon2's memory can't be locked |
| `fork` and daemonising | `fork` is unsafe in `nix`; spawning the same binary does the same job safely |
| An async runtime | a heavy dependency for one socket and one timer |
| libsodium bindings | C code through FFI, which conflicts with the "audited Rust crates, no unsafe in our crate" goal |
| Using the `age` format | built to encrypt whole files, not to look up, edit and rotate individual items |

## 15. Prior art

- **1Password CLI (`op`).** vaultline borrows its user-facing model: `op run` resolves `op://vault/item/field` references found in environment variables or an `--env-file`, and masks them in output by default. `op inject` fills in `{{ op://… }}` templates, and `op read` prints a single value. The differences: `op` is backed by a 1Password account, with sync, sharing and biometric unlock, and its key derivation combines the account password with a high-entropy Secret Key. vaultline is local-only, has no account, and protects the vault with a passphrase alone, so the passphrase and Argon2id carry all the weight. That is why D-001 and D-029 matter.
- **sops.** sops encrypts the values inside structured files (YAML, JSON, ENV, INI) with a data key, which is in turn encrypted for one or more master keys (cloud KMS, age, PGP). A MAC over the values detects tampering. Its files are meant to be committed to git. vaultline keeps the vault out of the repo, commits only reference files, and adds runtime injection with masking and an agent.
- **age.** age is a modern file-encryption tool. Its passphrase recipient uses scrypt, its payload is encrypted with ChaCha20-Poly1305 in fixed-size chunks, and its header is authenticated with HMAC-SHA-256. vaultline follows the same habits: one AEAD, a MAC'd header, small well-defined formats. It doesn't use the age format itself (§14).
- **Others.** `pass` and `gopass` encrypt one GPG file per secret. `envchain` keeps secrets in the OS keychain. `ssh-agent` is the model for the agent: a Unix socket, same-UID trust, and a timeout.
