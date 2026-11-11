# Decisions

Every question raised during planning and later phases, the options considered, the answer, and the reason. Entries are append-only: a reversed decision gets a new entry that points back to the one it replaces. Any approved change to `requirements.md`, `architecture.md`, `design.md`, `threat-model.md` or `vault-format.md` is logged here too.

Numbers in this file are chosen parameters and targets, not measurements. Measured values (unlock time, overhead, fuzzing hours) come only from scripts in the repo.

## Phase 0: planning

### D-001 · Argon2id parameters (PLAN §5.1)

- **Question:** Which Argon2id memory, iterations and parallelism, and what target unlock time?
- **Options:**
  - A: 64 MiB, t=3, p=4. RFC 9106's low-memory option. Light, but a modest cost for an attacker.
  - B: 256 MiB, t=3, p=4, aiming to unlock in 1 s or less on the developer Mac.
  - C: 2 GiB, t=1, p=4. RFC 9106's first choice. Strongest, but heavy for a CLI and for parallel tests.
- **Decision:** B. m = 256 MiB, t = 3, p = 4. Target: unlock in 1 s or less on the developer Mac.
- **Why:** An attacker guessing passphrases needs four times the memory of the RFC 9106 low-memory option, while unlocking still feels instant and runs on CI runners.
- **Constraints from the answer:** Nothing is installed on the Mac beyond Cargo crates, and no models are used. The `argon2` crate does the work. The test suite uses cheap parameters through an internal constructor so it doesn't hold 256 MiB per test. One fixture uses the real parameters.
- **Follow-through:** The parameters are stored in the vault header, so they can be raised without a format change. `init` refuses parameters below a floor, and the parser rejects values above a ceiling so a tampered header can't exhaust memory. The floor and ceiling are set in `vault-format.md`. Phase 2 adds a bench script that measures the real unlock time. If it misses the target, this decision is revisited.

### D-002 · Vault encoding, migration and the wording of S2 (PLAN §5.2)

- **Question:** JSON with base64, or a binary format? How does a v2 migrate v1 vaults?
- **Options:**
  - A: custom binary format. Magic bytes, version, length-prefixed little-endian fields, and a MAC over the whole file.
  - B: JSON with base64 through `serde_json`.
  - C: bincode or CBOR through serde.
- **Decision:** A, custom binary.
- **Why:** The spec can be exact to the byte. The MAC covers raw bytes, so there is no canonical form to get right. The parser is small and an obvious fuzz target. JSON makes authentication awkward. bincode's byte format depends on the crate version, which threatens fixtures that must open forever (S5).
- **Migration rules (accepted with A):** Every version's decoder is kept forever, and only the newest version is ever written. Upgrading is an explicit `migrate` command that replaces the file atomically. Nothing upgrades silently.
- **S2 wording (accepted with A):** S2 becomes "any changed byte is rejected with a format or authentication error, never wrong plaintext or a panic". A flipped length or magic byte fails parsing before any crypto runs. The invariants list in `CLAUDE.md` still says "authentication error". Updating it is the owner's call.

### D-003 · Associated data and whole-file integrity (PLAN §5.3)

- **Question:** Exactly what goes into each item's associated data, and which attacks does it stop?
- **Conflict resolved:** `CLAUDE.md` said "item ID as associated data". PLAN §3 said "vault id ‖ item id ‖ format version". This decision supersedes both.
- **Options:**
  - A: item ID only. This stops one item's ciphertext being moved into another's slot (S3), and nothing else.
  - B: the full AAD. Item AAD is version ‖ vault_id ‖ item_id. Each wrapped key gets the same AAD plus a key-type label. The master-key wrap covers the KDF parameters and salt.
  - C: B plus an HMAC-SHA-256 over every byte of the file, with the key derived from the master key through HKDF.
- **Decision:** C.
- **Why:** B stops slot swaps (S3), version confusion, and a wrapped key being decrypted as item data. It also binds every ciphertext to its vault identity, which matters only if two different vaults ever shared key material, for example through a future import feature or a bug. The file MAC also catches deleted, reordered or duplicated records, edits to unencrypted header fields, and records spliced in from another copy or an older snapshot of the same vault. It adds the RustCrypto `hkdf`, `hmac` and `sha2` crates.
- **Correction from the Phase 0 self-review:** The question shown to the owner said the associated data alone (option B) stops records moving between copies of a vault that share a master key. That was wrong. Copies share the same `vault_id`, so only the file MAC catches that. Option C, which was chosen, includes the MAC, so the decision stands, and the S3 tests are written to match (`design.md` §2).
- **Known risk:** Rolling back the whole file to an older copy can't be detected without state kept outside the vault. The threat model lists it.

### D-004 · What `passwd` and `rotate` re-encrypt (PLAN §5.4)

- **Question:** What does a passphrase change re-encrypt, and what does a master-key rotation re-encrypt?
- **Options:**
  - A: `passwd` re-wraps the master key. `rotate` makes a new master key and re-wraps the existing item keys, leaving item ciphertext as it is.
  - B: `passwd` re-wraps the master key. `rotate` makes a new master key and new item keys, and re-encrypts every item with fresh nonces.
  - C: `passwd` always does the full rotation.
- **Decision:** B.
- **Why:** `passwd` stays instant: a new salt, a new KEK, and the master key re-wrapped. But the master key doesn't change, so anyone who had the old file and the old passphrase can still decrypt the items in the new file. `rotate` is the fix: it revokes all old key material, including any item key that leaked. Re-encrypting a dev-sized vault costs almost nothing. The docs explain when to run `rotate` after `passwd`.

### D-005 · What the vault file reveals without the passphrase (new)

- **Question:** What can someone with the vault file but not the passphrase learn, for example from a stolen backup or a file pushed to a repo?
- **Options:**
  - A: project, item and field names in plaintext, so `list` works without unlocking.
  - B: names inside each item's ciphertext, with random 128-bit item IDs.
  - C: B, plus padding every item up to a fixed size bucket.
- **Decision:** B.
- **Why:** Names like `acme-prod/stripe/live_key` show an attacker what's worth going after and reveal how projects are laid out. The cost of encrypting them is small: `list` needs an unlock, and a lookup decrypts items, which is cheap for a dev-sized vault.
- **Known risk:** The file still reveals the vault ID, the KDF parameters, how many items there are and roughly how big each one is. Size padding goes under Follow-ups.

### D-006 · Which numbers may appear in docs (new; how to read a `CLAUDE.md` rule)

- **Question:** `CLAUDE.md` says never to put a number in `README.md` or `docs/` unless a script in the repo produced it. But the Phase 0 docs need chosen parameters and targets. How does the rule apply?
- **Options:**
  - A: the rule covers measurements only.
  - B: chosen numbers live only in `decisions.md`, and other docs point to a decision ID.
  - C: strict, so every number comes from a script.
- **Decision:** A.
- **Meaning:** Measured results appear in `README.md` and `docs/` only when a script in the repo produced them, and the doc names that script. Measured results include unlock time, `run` overhead, fuzzing CPU-hours, crash counts, test counts and benchmark figures. Chosen parameters and targets may appear, labelled as parameters or targets, never as results achieved.

### D-007 · Masking a secret split across chunks, and very short secrets (PLAN §5.5)

- **Question:** How does masking handle a secret split across output chunks, and very short secrets?
- **Options:**
  - A: hold back only the tail that could be the start of a secret, mask every secret, and warn about short ones.
  - B: the same matching, but skip secrets below a minimum length.
  - C: buffer and mask one line at a time.
- **Decision:** A.
- **Design:** stdout and stderr each go through their own streaming multi-pattern matcher, using the `aho-corasick` crate (justified in the Phase 3 PR). The matcher works like this:
  - Bytes are written out right away, except the longest tail of the buffer that is a proper prefix of some secret.
  - That tail is held until it either completes a match, which is replaced with a fixed marker, or can no longer match, in which case it is written out.
  - Everything left is flushed at end of stream.
  - Output is delayed only while it ends in what could be the start of a secret.
  - Every secret is masked whatever its length. A secret below a minimum length (set in `design.md`) triggers a warning on stderr, because masking it can garble output.
- **Known limits:** The child has the secret in its environment, so masking only catches secrets printed by accident. It does not stop a child that sets out to leak one. It also misses encoded forms (base64, URL encoding, hex), output the child writes directly to `/dev/tty` or to files, and a secret split between stdout and stderr.

### D-008 · How `run` decides which secrets to inject (new)

- **Question:** How does `vault run -- <cmd>` decide which secrets go into the child's environment?
- **Options:**
  - A: resolve any environment variable whose value is a `vault://` reference, plus `--env-file` with `NAME=vault://...` lines.
  - B: `--env-file` only.
  - C: one `--env NAME=vault://...` flag per secret.
- **Decision:** A.
- **Why:** Reference files hold no secrets, so they can be committed. It is the model users already know from 1Password's `op run`.
- **Left to Q24:** what wins when the inherited environment and the env file set the same name, and whether a reference may sit inside a longer value.

### D-009 · How `run` connects the child to the terminal (new)

- **Question:** `run` has to sit between the child and the terminal to mask output. How should it connect them?
- **Options:**
  - A: pipes, plus a `--no-mask` escape hatch.
  - B: a pseudo-terminal (PTY).
  - C: pipes, always masked.
- **Decision:** A.
- **Design:**
  - The child's stdout and stderr are pipes read by the masker. stdin is inherited directly.
  - SIGINT, SIGTERM and SIGHUP are forwarded to the child.
  - `run` exits with the child's exit code, or 128 + the signal number if the child was killed by a signal.
  - `--no-mask` gives the child the real terminal and prints a warning. S7 does not apply when `--no-mask` is used, and the docs say so.
- **Why:** Pipes need no unsafe code, while a PTY needs a controlling terminal, which means unsafe `pre_exec` code (ruled out by `#![forbid(unsafe_code)]`) or an extra crate. A PTY also merges stdout and stderr.
- **Superseded in part:** D-036 replaces how SIGINT is handled.
- **Known cost:** The child doesn't see a terminal, so colours may drop and some programs buffer their output. PTY support goes under Follow-ups.

### D-010 · Where `inject` may write (PLAN §5.8)

- **Question:** Does `inject` write only to stdout, or also to a named pipe?
- **Options:**
  - A: stdout only, refusing when stdout is a regular file, with no override.
  - B: stdout only, with no check.
  - C: stdout, plus `-o` for a FIFO that is checked after opening.
- **Decision:** A.
- **Design:** `inject` checks fd 1 with `fstat` before resolving any reference. If it is a regular file, it exits with an error that explains why and writes nothing. Pipes, terminals and `>(...)` process substitution all work.
- **Why:** This stops the common accident of `> config.yml` putting plaintext on disk. It is a guard against accidents, not a security boundary: `| cat > file` still gets through, and the threat model says so. A named pipe adds code and a race to test, for little gain over `>(...)`.

### D-011 · How `set` takes values and `get` returns them (new)

- **Question:** How do secret values get into and out of the vault on the command line?
- **Options:**
  - A: `set` reads from a hidden prompt or from stdin, and `get` prints to stdout.
  - B: like A, but `get` needs `--reveal`.
  - C: like A, but `set` also accepts the value as an argument.
- **Decision:** A.
- **Design:** `set` reads the value from a hidden terminal prompt, or from stdin when stdin is not a terminal. It never takes the value as an argument, because arguments land in shell history and show in `ps`. `get vault://project/item/field` prints the raw value to stdout, with the same regular-file refusal as `inject` (D-010).

### D-012 · Supplying the passphrase without a prompt (new)

- **Question:** Tests and scripts have to unlock without anyone typing. How may the passphrase be supplied?
- **Options:**
  - A: `--passphrase-stdin` only.
  - B: also a `VAULTLINE_PASSPHRASE` environment variable.
  - C: `--passphrase-fd N`.
- **Decision:** A.
- **Design:** With `--passphrase-stdin`, the passphrase is read from stdin. Without it, a terminal prompt runs with echo off. There is no environment variable.
- **Why:** Environment variables are inherited by every child process. Other processes running as the same user can read them (`/proc/<pid>/environ` on Linux), and they turn up in crash reports.
- **Left to Q24:** how `set --passphrase-stdin` tells the passphrase apart from the value when both arrive on stdin.

### D-013 · How the agent identifies callers, and its idle timeout (PLAN §5.6)

- **Question:** How does the agent identify the caller on Linux and on macOS? What is the idle timeout?
- **Options:**
  - A: peer UID check with a 15-minute idle timeout.
  - B: the same, plus an 8-hour hard cap.
  - C: the same check with a 5-minute timeout.
  - D: the same check with a 1-hour timeout.
- **Decision:** A.
- **Design:**
  - **Caller identity:** On Linux the caller's UID comes from `SO_PEERCRED`. On macOS it comes from `getpeereid`. Both are called through `nix`, so no unsafe code is needed.
  - **Refusal:** A connection whose UID differs from the agent's effective UID is closed before any message is read.
  - **Socket location:** The socket lives in a directory with mode 0700. At startup the agent checks that directory's owner and mode and refuses to start if either is wrong.
  - **Idle timeout:** The master key is wiped after 15 minutes without an accepted request. A flag changes the timeout. Only accepted requests reset the clock.
  - **Other wipes:** The key is also wiped on `vault lock` and when the agent stops for any reason.
- **Known risk:** Any process running as the same user can ask the agent for secrets. That is the "malware running as you" case, which the threat model puts out of scope.

### D-014 · What the agent does, and how it starts and stops (new)

- **Question:** Is the agent required, and what does it hand out?
- **Options:**
  - A: optional, and the agent does the decrypting.
  - B: required, and the agent does the decrypting.
  - C: optional, and the agent hands out item keys.
- **Decision:** A.
- **Design:**
  - **With an agent:** Commands send their requests to the agent if one is running. The agent returns only the field values asked for, and the master key never leaves the agent process.
  - **Without an agent:** Commands prompt for the passphrase, do the work in-process and wipe the key when they exit.
  - **Starting:** `vault unlock` starts the same binary in agent mode as a background child in its own process group, with stdio detached. There is no `fork()` in our code. The passphrase reaches the agent through a pipe, never through arguments or the environment.
  - **Stopping:** `vault lock` wipes the key, and `vault agent stop` ends the agent.
  - **Tests:** Every test stops every agent it starts.
- **Why:** Everything works with no background process, and both paths share the same core code. Keys stay inside a single process.

### D-015 · How the audit log catches truncation (PLAN §5.7)

- **Question:** How does the audit log detect truncation, not just edits?
- **Options:**
  - A: a head file plus an anchor saved outside the vault.
  - B: the head stored inside the vault file.
  - C: a head file only.
- **Decision:** A.
- **Design:**
  - **Head record:** After every append, a head record is replaced atomically. It holds the entry count and the hash of the last entry, and is MAC'd with the audit key.
  - **What `vault audit verify` checks:** that the chain links up, that every MAC is valid, and that the log reaches the head.
  - **Anchors:** `vault audit head` prints the current anchor. `vault audit verify --expect <anchor>` checks that the log still contains that entry at that position. The log may have grown since the anchor was saved.
- **Known risk:** If the log and the head are rolled back together to an earlier state that is consistent, nothing catches it unless an anchor was saved somewhere else.
- **Scope note:** `audit head` and `--expect` are additions to PLAN §2.

### D-016 · How audit entries are authenticated, and what they contain (new)

- **Question:** How are audit entries authenticated, and what do they hold?
- **Options:**
  - A: a keyed MAC, with item IDs only.
  - B: a keyed MAC, with names included.
  - C: an unkeyed hash chain.
- **Decision:** A.
- **Design:**
  - **MAC:** Each entry gets an HMAC-SHA-256. The key is derived from the master key with HKDF, using a different label from the file-MAC key.
  - **Entry contents:** sequence number, timestamp, event type, item ID where one applies, and the previous entry's hash. Entries never hold secret values, names or the passphrase.
  - **Verification:** `audit verify` needs an unlock, either directly or through the agent.
- **Failed unlocks:** These can't be MAC'd, because no key exists yet. They are tallied in a small unauthenticated counter. The next successful unlock appends an authenticated entry that records the tally, marked as unverified. Someone with disk access can reset the counter, and the threat model says so.
- **Why:** Anyone with disk access can rewrite an unkeyed chain so it still checks out. Putting names in entries would undo D-005.
- **Superseded in part:** D-034 replaces how the audit key is derived.

### D-017 · Process hardening (new)

- **Question:** What should the CLI and agent do to keep secrets out of crash dumps, debuggers and swap, without unsafe code?
- **Options:**
  - A: no core dumps, plus marking the process non-dumpable on Linux.
  - B: A plus `mlock` on secret memory.
  - C: rely on zeroize only.
- **Decision:** A.
- **Design:**
  - **Core dumps:** Every process that may touch a secret sets its own core-dump limit to 0 at startup, using `setrlimit(RLIMIT_CORE)` through `nix`. This covers the agent too.
  - **Linux:** The process also calls `prctl(PR_SET_DUMPABLE, 0)` through `nix`. That stops other processes running as the same user from attaching with ptrace or reading `/proc/<pid>/mem`. These settings change only the tool's own processes, never system settings.
  - **Secret types:** Secrets live in `secrecy`/`zeroize` types that implement neither Debug nor Display.
  - **Panics:** Panics unwind (the default), so wipe-on-drop still runs. No panic message contains a secret.
- **Why not `mlock`:** It needs another crate and runs into Linux's default locked-memory limit. Argon2's 256 MiB working memory couldn't realistically be locked anyway.
- **Known risks:** Secrets can reach swap and hibernation files. macOS encrypts swap by default, while on Linux it depends on configuration. Zeroize can't reach copies outside our process: kernel pipe buffers, the child process, or the terminal's scrollback.

### D-018 · Repo visibility and fuzzing budget (PLAN §5.11)

- **Question:** How long does the fuzz campaign run on GitHub Actions, split into how many jobs, and does it fit the free minutes? The repo is private: 2,000 Linux minutes a month, with macOS minutes counting 10×.
- **Options:**
  - A: public before Phase 1.
  - B: private until Phase 5, then public.
  - C: private throughout, with a short campaign.
- **Decision:** A. The owner switches the repo to public before Phase 1 starts. Claude does not change repo settings.
- **Campaign:** Four targets, one job per target:
  - the vault file parser
  - the `vault://` reference parser
  - the template parser
  - the agent message decoder

  Each job runs for up to 6 hours, GitHub's limit for a single job. The owner starts the campaign once or twice in Phase 5 with `gh workflow run fuzz-campaign.yml`. Exact durations go in `phases.md`.
- **Why:** Public repos get unlimited Actions minutes, so CI and a real campaign both fit.
- **Heads-up:** Everything already committed becomes public too, including `PLAN.md` (target employers, resume line) and `CLAUDE.md`. The owner may want to trim or move them before switching.
- **Unchanged:** The CI rule in `CLAUDE.md` stays: the Linux job runs on every push, and the macOS job runs on pull requests.

### D-019 · License (new)

- **Question:** Which license should the repo carry?
- **Options:**
  - A: MIT OR Apache-2.0.
  - B: MIT.
  - C: no license.
- **Decision:** A, MIT OR Apache-2.0, the standard dual license in the Rust ecosystem. Phase 1 adds `LICENSE-MIT` and `LICENSE-APACHE` and sets `license` in `Cargo.toml`.

### D-020 · Standing constraint: nothing risky on the developer Mac (from the answers to Q1 and Q16)

The owner asked twice that nothing done for this project cause problems on their Mac. This builds on the hard limits in `CLAUDE.md` and governs every phase:

- **Installs:** Nothing is installed or updated: no `brew`, no `cargo install`, no `rustup` toolchains or components, no installers. Nothing is downloaded or run except crates fetched by Cargo.
- **Where work happens:** Work stays inside the project folder, Cargo's own cache, and temporary directories that each test creates and removes.
- **Background processes:** Nothing keeps running after a command finishes. Every test stops every agent it starts and uses sockets in its own temporary directory.
- **Resources:** Tests use cheap Argon2 parameters, so the suite stays light on memory and CPU. The real 256 MiB parameters are used only during a real unlock, by one `init` test, by one fixture test, and by `make bench`. `make bench` runs only when asked for and finishes quickly.
- **Settings:** Hardening settings (D-017) apply only to the tool's own processes. No system setting is changed.
- **Heavy work:** The fuzz campaign and the Linux test runs happen on GitHub's servers. Local fuzzing is a short smoke run at most.
- **Amended:** D-040 adds one `passwd` test and one `rotate` test per phase to the tests that use the 256 MiB parameters.

### D-021 · Supported operating systems (PLAN §5.9)

- **Question:** Which OSes are supported?
- **Options:**
  - First pass: A, macOS and Linux. B, the same plus more architectures. C, Linux only. The owner answered "macOS".
  - Clarifying pass: A, macOS, plus Linux tested in CI only. B, macOS only, which would change the CI rule in `CLAUDE.md`.
- **Decision:** macOS on Apple Silicon is the platform used day to day. Linux x86_64 is supported and tested only on GitHub's servers, so nothing Linux-related runs on the Mac. Windows is not supported: building on a non-Unix target fails with a clear `compile_error!`. Other architectures may work but aren't tested.
- **Why:** The Linux-only hardening and peer-check code (D-013, D-017) gets tested in CI, and the CI rule in `CLAUDE.md` stays as it is.

### D-022 · Tools that aren't installed locally (new)

- **Question:** `cargo-deny`, `cargo-audit` and `cargo-fuzz`, plus the nightly toolchain that `cargo-fuzz` needs, are not installed on the Mac. Installing them is off-limits for Claude. Local Rust is 1.86.0. How do phases 1–5 handle that?
- **Options:**
  - A: run those tools only in CI.
  - B: the owner installs them.
  - C: drop them.
- **Decision:** A.
- **Design:**
  - **Local behaviour:** `make audit` and `make fuzz` check whether the tool is present. If it isn't, they print a message saying the check runs in CI.
  - **Where the tools run:** CI installs and runs `cargo-deny`, `cargo-audit` and `cargo-fuzz`, with nightly for fuzzing only, on GitHub's runners.
  - **Toolchain:** The project targets Rust 1.86 through `rust-version` in `Cargo.toml`, and CI pins 1.86 for build, lint and test so local and CI results match. There is no `rust-toolchain.toml`, because pinning an exact version there would make rustup download a toolchain on the Mac.
  - **The fuzz crate:** It stays outside the main workspace, so stable `cargo test` never builds it.
- **Workflow change:** Step 4 of the phase workflow becomes: `make lint` and `make test` pass locally, then the branch is pushed and the CI audit and fuzz-smoke jobs must pass before the PR is opened. The workflow text in `CLAUDE.md` still lists `make audit` as a local check. Updating it is the owner's call.

### D-023 · Shell-plugin side quest (PLAN §5.10)

- **Question:** Shell-plugin side quest: yes or no?
- **Options:**
  - A: skip it.
  - B: decide in January.
- **Decision:** A, skip. 1Password's shell-plugins repo is written in Go, and Go is not installed on the Mac (D-020). It is listed under Follow-ups in case it's picked up later.

### D-024 · Binary name (new)

- **Question:** PLAN calls the command `vault`, which clashes with HashiCorp Vault's widely installed CLI. What should it be called?
- **Options:**
  - A: `vaultline`.
  - B: `vl`.
  - C: `vault`.
- **Decision:** A. The binary, crate and data directory are all named `vaultline`. References keep the `vault://project/item/field` scheme from PLAN. Where PLAN says `vault run`, `vault inject` and so on, the docs say `vaultline run`, `vaultline inject` and so on.

### D-025 · Data model and file locations (new)

- **Question:** How are secrets organised, and where do the files live?
- **Options:**
  - A: one vault file holding many projects.
  - B: one vault file per project.
  - C: one vault with no projects, which would break the `vault://project/item/field` format.
- **Decision:** A.
- **Design:**
  - **Structure:** One vault file holds every project. A project holds items, and an item holds named fields. A reference `vault://project/item/field` points to exactly one field value.
  - **Passphrase and agent:** One passphrase and one agent cover the whole vault.
  - **Location:** The vault, audit log, audit head and agent socket live in `~/.vaultline/`, mode 0700. Setting `VAULTLINE_DIR` points them elsewhere. Tests use that to work in their own temporary directories.

### D-026 · How references appear in `inject` templates (new)

- **Question:** How do references appear in the templates that `inject` fills in?
- **Options:**
  - A: `{{ vault://project/item/field }}` only.
  - B: bare `vault://` references.
  - C: both.
- **Decision:** A.
- **Design:** Only text of the form `{{ vault://… }}` is replaced. Whitespace inside the braces is optional. Other `{{ }}` templating, such as Helm or Jinja, passes through unchanged, and so does plain text that mentions `vault://` without braces. Because the braces mark the end, a reference can sit inside a URL or a quoted string. This matches 1Password's `op inject`.

### D-027 · Smaller defaults, part 1 (new)

- **Question:** The owner accepted two of the four default groups as written. The other two are being asked item by item in D-028 onwards.
- **Accepted, storage and files:**
  - Every save writes a temporary file in the same directory, flushes it to disk, then renames it over the old one. A crash never leaves a half-written vault, and the temporary file holds only ciphertext.
  - A lock file stops two writers clashing.
  - Directories are 0700 and files 0600.
  - If the socket path would exceed macOS's 104-byte limit, the agent stops with a clear error.
- **Accepted, names and size limits:**
  - Project, item and field names use letters, digits, `.`, `_` and `-`. They are 1–64 bytes long and case-sensitive.
  - A reference is exactly `vault://project/item/field`.
  - The parsers cap input sizes: a value is at most 64 KiB, a vault file at most 64 MiB, and an agent message at most 1 MiB. Anything larger is rejected cleanly.

### D-028 · How `run`, `inject` and `get` behave (Q24a–d)

- **Unresolved references (Q24a).** Options: fail and do nothing; warn and skip; or a flag to choose. **Decision:** fail and do nothing. If any reference can't be resolved, `run` doesn't start the child, and `inject` and `get` write nothing to stdout. The error names the bad reference.
- **References inside longer values in `run` (Q24b).** Options: the whole value only; or allow `{{ vault://… }}` inside values. **Decision:** the whole value only. A variable is resolved only when its entire value is a `vault://` reference. Composed values such as URLs use `inject`, or get stored as their own field.
- **Name clash between the environment and `--env-file` (Q24c).** Options: the env file wins; the environment wins; or refuse. **Decision:** the env file wins. A note on stderr names the overridden variable, giving the name only and never the value.
- **Mask marker and short secrets (Q24d).** Options: `<concealed by vaultline>` with a warning under 8 bytes; `***` with the warning; or the marker with no warning. **Decision:** each masked secret is replaced by `<concealed by vaultline>`. Any secret shorter than 8 bytes triggers a warning on stderr at start-up, because masking it can garble output. This sets the minimum length that D-007 left open.

### D-029 · Input rules and scope (Q24e, f, h)

- **Passphrase rule (Q24e).** Options: at least 12 characters; a strength estimator; or no rule. **Decision:** at least 12 characters at `init` and `passwd`, with no strength meter and no extra crate. The prompt suggests using several random words.
- **Values on stdin (Q24f).** Options: strip one trailing newline and take the passphrase from the first line; strip one newline and never mix passphrase and value; or keep the bytes exactly. **Decision:** the first option.
  - A value read from stdin loses exactly one trailing newline, and `--raw` keeps the bytes exactly.
  - With `set --passphrase-stdin`, the first line of stdin is the passphrase and everything after it is the value. This settles the question D-012 left open.
- **Scope (Q24h).** Options: build `migrate` later, with a scripted video; build `migrate` later and drop the video; or build `migrate` in v1. **Decision:** the first option.
  - The v1 docs set the migration rules (D-002), and the `migrate` command is built only once a v2 format exists.
  - In Phase 5 Claude writes a shot-by-shot script for the demo video, and the owner records it.

### D-030 · Which events the audit log records (Q24g)

- **Question:** Which events go into the audit log?
- **Options (multi-select):** unlock, lock and failed unlocks; reads; writes; verify runs. The first answer left out writes. A clarifying question pointed out that PLAN §3 logs every write, and that a deleted or rotated secret would otherwise leave no trace.
- **Decision:** all four groups:
  - unlock, lock, idle timeout, and the failed-unlock tally (D-016)
  - every read by `get`, `run` or `inject`
  - every write: `set`, `rm`, `passwd`, `rotate`, and later `migrate`
  - every `audit verify` run and its result

  Entries carry item IDs only, never values or names (D-016).

### D-031 · Target for `run` startup overhead (new)

- **Question:** PLAN asks for `run`'s startup overhead to be published. Should there be a target it must meet?
- **Options:**
  - A: 50 ms or less with an agent.
  - B: 200 ms or less with an agent.
  - C: no target, just a measurement.
- **Decision:** A. With an unlocked agent, `run` adds at most 50 ms before the child starts. That covers the socket round trip, decryption and spawning the child. Without an agent, unlock time dominates, and D-001's target applies. A bench script measures it in Phase 5.

### D-032 · Fuzz smoke runs in CI (new)

- **Question:** How should CI smoke-test the fuzz targets, separately from the long campaign?
- **Options:**
  - A: 60 s per target on every push.
  - B: 60 s per target on PRs only.
  - C: 5 min per target on PRs only.
- **Decision:** A. Every Linux CI run fuzzes each existing target for 60 seconds on GitHub's runners. This is what `make fuzz` runs in CI (D-022).

### D-033 · Bringing `CLAUDE.md` in line with the decisions (new)

- **Question:** Some answers contradict lines in `CLAUDE.md`: the S2 wording (D-002), "item ID as associated data" (D-003), and running `make audit` locally (D-022). How should `CLAUDE.md` be updated?
- **Options:**
  - A: Claude updates it in the Phase 0 PR.
  - B: the owner edits it.
  - C: leave it, and let the docs win.
- **Decision:** A. The Phase 0 PR edits only those lines, each pointing to its decision. The owner reviews the change in the diff.

### D-034 · An audit key that doesn't depend on the master key (supersedes the key derivation in D-016)

- **Question:** This flaw turned up while checking the design. D-016 derived the audit MAC key from the master key. But `rotate` replaces the master key (D-004), so after any rotation every older entry would fail verification, and `audit verify` would reject a perfectly good log.
- **Options:**
  - A: a separate random audit key, stored wrapped under the master key and re-wrapped on `rotate`.
  - B: keep deriving the key from the master key, and start a new log after each `rotate`, which loses verifiable history.
  - C: a new audit key on every `rotate`, with a committed handover and old keys kept.
- **Decision:** A.
- **Design:**
  - `init` generates a random 32-byte audit key and stores it in the vault header, wrapped under the master key's wrapping subkey with its own associated data.
  - `rotate` re-wraps the same audit key under the new master key, and `passwd` leaves it alone. The whole log stays verifiable across rotations.
  - The wrapped key is a fixed 72-byte record in the v1 header, so Phase 2 includes it before the v1 fixtures are frozen, even though the audit log itself arrives in Phase 4.
- **Known risk:** The audit key never changes. Anyone who once obtained it, for example by reading an unlocked agent's memory (out of scope), could forge entries from then on. Rotating the audit key is a Follow-up.

### D-035 · Changes to the PLAN phase order (proposed by Claude while writing `phases.md`; to be confirmed in the Phase 0 PR review)

- **Vault-file fuzz harness: Phase 2.** It moves into Phase 2, where the vault parser is written. The reference and template harnesses arrive in Phase 3, and the agent-message harness in Phase 4.
- **`fuzz-campaign.yml`: Phase 4.** It moves from Phase 5 to Phase 4. GitHub only allows a workflow to be started by hand (`workflow_dispatch`) once the workflow file is on the default branch. With the file on `main` after Phase 4, the owner can start the campaign at the beginning of Phase 5, and the Phase 5 PR carries the fixes and the published numbers.
- **Audit-key record: Phase 2.** The wrapped audit key (D-034) is part of the v1 format from Phase 2.

### D-036 · How `run` handles signals (supersedes the SIGINT handling in D-009)

- **Question:** This flaw turned up in the Phase 0 self-review. Ctrl-C makes the terminal send SIGINT to the whole foreground process group, so vaultline and the child both receive it. If vaultline also forwarded SIGINT, the child would get it twice, and many programs treat a second Ctrl-C as "force quit".
- **Options:**
  - A: behave like POSIX `system()`.
  - B: forward SIGINT only when another process sent it, using the signal's sender information.
  - C: put the child in its own process group and hand it the terminal.
- **Decision:** A.
- **Design:**
  - While the child runs, vaultline ignores SIGINT and SIGQUIT. The child receives them directly from the terminal, exactly once.
  - SIGTERM and SIGHUP are forwarded to the child.
- **Why:** This is the same rule C's `system()` uses. It is simple and testable on both OSes: a test sends SIGINT to the process group, just as the terminal would. B relies on sender information that isn't reliable across macOS and Linux, and a signal aimed at the whole group would still arrive twice. C needs to switch the terminal's foreground group, which involves timing races.
- **Known limits:**
  - `kill -INT <vaultline pid>` sent by another process doesn't reach the child. Send SIGTERM instead.
  - A SIGTERM or SIGHUP aimed at the whole process group, such as a shell's `kill %1`, reaches the child twice.

  The docs record both.

### D-037 · Design details Claude chose while writing the Phase 0 docs (to review in the PR)

None of these change an answer above. Each fills in a detail the answers left open. Objections in the PR review become new decisions.

- **Locked agent:** commands fall back to the in-process prompt, and the agent stays locked.
- **Idle timeout:** the agent wipes the key, appends `idle-timeout`, removes its socket and exits, so nothing lingers. `lock` keeps the agent running.
- **Key-changing commands:** `init`, `passwd` and `rotate` always run in-process and always ask for the current passphrase, even when an agent is unlocked. `rotate` then locks a running agent.
- **Argon2 parameters on rewrite:** `passwd` and `rotate` write the current default Argon2id parameters, which is how a vault's parameters get raised (D-001).
- **Argon2 parameter ceilings in the v1 parser:** memory up to 1 GiB, at most 10 iterations, at most 8 lanes. Opening a vault weaker than the defaults prints a warning that suggests `passwd`.
- **Order of `--passphrase-stdin` lines:** passphrases are read one per line, in the order the command asks for them. `passwd` takes the current passphrase, then the new one. Everything after the passphrase lines is the command's own input: the value for `set`, the template for `inject`, the child's stdin for `run`. The lines are read one byte at a time, so nothing meant for the rest of stdin gets consumed.
- **Env files:** values that aren't references are passed through as literals. There is no quoting and no expansion. Carriage returns and duplicate names are rejected.
- **Size caps:** templates and env files are limited to 16 MiB.
- **Waits and timeouts:** a second writer waits up to 10 s for the writer lock. The agent closes a connection that sends nothing for 5 s.
- **Idle-timer resets:** only Resolve, Set, Remove, List, AuditVerify and AuditHead reset the idle timer. Status, Lock and Stop don't.
- **Peer checks both ways:** the client checks the agent's UID, as well as the agent checking the client's.
- **`list` and the audit log:** `list` returns no values, so it isn't logged as a read. `audit verify` holds the writer lock while it reads.
- **Exit codes:** 0 for success, 1 for a vaultline error, 2 for a usage error. `run` passes on the child's code, with 126 or 127 when the child can't be started, and 128 + N when the child is killed by signal N.
- **Not using `serde`:** `serde`, from PLAN's stack, isn't used. Both formats and the wire protocol are specified by hand.
- **Argon2 lane parallelism:** the `argon2` crate computes its lanes one after another unless its `parallel` feature (which uses `rayon`) is on. Phase 2 measures unlock time first. If the target is missed, that feature is one option to raise (D-001).

## Phase 2: crypto core and vault format

### D-038 · RustCrypto crate generation and the OS random generator (Phase 2)

- **Question:** Two generations of the RustCrypto crates build with Rust 1.86. The docs said randomness comes from `getrandom` through `rand_core::OsRng`, but the current `rand_core` (0.10) no longer has `OsRng`. Which generation should vaultline use, and how does it reach the OS generator?
- **Options:**
  - A: the current generation (`argon2` 0.6, `chacha20poly1305` 0.11, `hkdf` and `hmac` 0.13, `sha2` 0.11), calling the OS generator directly with `getrandom::fill` (`getrandom` 0.4).
  - B: the previous generation (`argon2` 0.5, `chacha20poly1305` 0.10, `hkdf` and `hmac` 0.12, `sha2` 0.10), with `rand_core` 0.6 and its `OsRng`, as the docs said.
- **Decision:** A.
- **Why:** It is the maintained line, it is already widely used, and fixes land there first. The algorithms are the same, so the format doesn't change.
- **Doc changes (approved):** `vault-format.md` §2 and `design.md` §13 name `getrandom` as the source of keys, salts, nonces and IDs, and `phases.md` Phase 2 says "randomness from `getrandom` only". `rand_core` is not a dependency.

### D-039 · Secret types and `Debug` (corrects `design.md` §10)

- **Question:** `design.md` §10 said `SecretString`, `SecretBox<[u8]>` and `Zeroizing<[u8; 32]>` implement neither Debug nor Display. They do: secrecy's types print `[REDACTED]`, and `Zeroizing<[u8; 32]>` prints the raw bytes. How should the sentence be handled?
- **Options:**
  - A: fix the sentence. The library types are used only inside the wrappers in `src/secret.rs`, and the wrappers implement neither trait.
  - B: leave the doc as it is.
- **Decision:** A.
- **Design:** `Key`, `Passphrase`, `SecretValue` and `SecretBytes` in `src/secret.rs` hold the library types and implement neither trait. So do the types that hold them (`Vault`, `Item`, `Payload`, `Subkeys`). `tests/adversarial/secret_types.rs` checks every one with `static_assertions`.
- **Doc change (approved):** the "Secret types" bullet in `design.md` §10.

### D-040 · Tests that run Argon2id at the default parameters (amends D-020)

- **Question:** D-020 lists one `init` test, one fixture test and `make bench` as the only users of the 256 MiB parameters. But `passwd` and `rotate` always write the default parameters (`vault-format.md` §4.8), and P2-6 checks that, so any test that calls them runs Argon2id at 256 MiB. How should Phase 2, and later Phase 3's CLI tests, handle this?
- **Options:**
  - A: `passwd` and `rotate` have no parameter override. Each phase that tests them adds one `passwd` test and one `rotate` test at the real parameters, run one at a time.
  - B: a test-only parameter override keeps most tests cheap, with one test each at the defaults.
- **Decision:** A.
- **Why:** No code path exists, not even one compiled only for tests, that could make `passwd` or `rotate` write weaker parameters.
- **Effect on D-020:** the 256 MiB parameters are also used by one `passwd` test and one `rotate` test in Phase 2 (`src/vault/tests.rs`) and in Phase 3 (the CLI). They take a lock, so they never run at the same time.
- **Local runs:** the owner agreed that Claude runs `make bench` once on the developer Mac in Phase 2, for P2-15.
- **Doc change (approved):** the "Cheap parameters" bullet in `design.md` §12.2.

### D-041 · Files in the vault directory are checked too (threat model C13)

- **Question:** `threat-model.md` C13 says the directory and the files are private to the user and vaultline refuses to use them otherwise. P2-10 only says files are created with mode 0600 and a bad directory is refused. Should files be checked as well?
- **Options:**
  - A: also refuse a vault or lock file that is a symlink, isn't a regular file, is owned by another user, or gives group or others any access.
  - B: check the directory only.
- **Decision:** A.
- **Design:** files are opened with `O_NOFOLLOW` and checked through their own descriptor (`fstat`), so the check applies to exactly the file that is read or locked. A refusal prints the `chmod` or `chown` that fixes it, as for the directory (`design.md` §11). Tested in `tests/adversarial/permissions.rs`.

### D-042 · What P2-13 checks

- **Question:** P2-13 says no name or value from the fixtures or from proptest-generated vaults appears in the vault bytes. Strings of 1 to 7 bytes, such as a 1-byte name or the empty value, turn up in random ciphertext by chance, so they can't be checked. What does the test check?
- **Options:**
  - A: every name and value of 8 bytes or more. The proptest generator for this test makes distinctive `fake-…` markers of 8 bytes or more. The fixtures keep their short names, a useful edge case, and those are skipped.
  - B: make every fixture and generated name and value 8 bytes or more, so nothing is skipped.
- **Decision:** A. The test's documentation states the limit.

### D-043 · Argon2id's working memory (implementation note; no doc change)

- **Found while wiring Argon2id:** in `argon2` 0.6, the allocating `hash_password_into` frees its working memory without wiping it, even with the `zeroize` feature. That feature only wipes the initial and final hashes. `design.md` §10 says the working memory is wiped.
- **Implementation:** `vault::crypto::derive_kek` allocates the memory blocks itself, in a `Zeroizing<Vec<Block>>`, and passes them to `hash_password_into_with_memory`, so they are wiped before they are freed. The statement in `design.md` §10 holds, so no doc change is needed.
- **Related:** `hmac` and `sha2` are built with their `zeroize` features, so HMAC and SHA-256 states are wiped on drop. `argon2`'s `zeroize` feature doesn't turn on `blake2`'s, so `blake2` is listed as a direct dependency only to turn its `zeroize` feature on; the BLAKE2b states that Argon2id feeds the passphrase through are then wiped as well.
