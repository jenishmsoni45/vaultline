# Talk outline: 20 minutes

An outline for a 20-minute talk on vaultline (P5-5). The minutes below are a time budget, not a measurement. Every claim in the talk is one of C1–C13 in `docs/threat-model.md` §7, and any number comes from `scripts/numbers.sh` (D-006).

## Sections

| # | Section | Minutes |
|---|---|---|
| 1 | The problem: where secrets leak today | 2 |
| 2 | The threat model: who, what, and what is out of scope | 3 |
| 3 | The key hierarchy and the vault format | 4 |
| 4 | Injection without plaintext: `run`, `inject` and masking | 3 |
| 5 | The agent and the audit log | 3 |
| 6 | How it was tested: invariants, fuzzing and the postmortem | 3 |
| 7 | Limits, and questions | 2 |

## 1. The problem (2 min)

- `.env` files in repositories, secrets in shell history, tokens printed by CI.
- Goal: the secret exists in plaintext only in memory, only while it is needed.
- Show: the README's first paragraph and the demo's first minute (`docs/demo-script.md`).

## 2. The threat model (3 min)

- Adversaries T1 to T5: the offline thief, the repo leak, another local user, accidental exposure, the offline tamperer.
- Out of scope, and why: malware running as the user (T7), and root or physical access (T8). `ssh-agent` draws the same line.
- Claims C1–C13, each with a test. A claim without a test isn't made.
- Ask the room: what would you add?

## 3. Keys and format (4 min)

- Argon2id turns the passphrase into a key; that key unlocks a master key; the master key unlocks per-item keys (D-003).
- XChaCha20-Poly1305 per item, with the format version, vault ID and item ID as associated data. Why the item ID is bound: moving one item's ciphertext into another slot fails (C3).
- An HMAC over the whole file catches deleted, reordered and spliced records (C2).
- Why these Argon2id parameters (D-001); why envelope encryption and not one key.
- No cipher, KDF or MAC was written here: the RustCrypto crates only.

## 4. Injection and masking (3 min)

- `run` resolves every reference first, all or nothing, then spawns the child with the secrets in its environment (C6).
- Masking works on a stream, not on chunks: a secret split across reads is still caught (C7, D-007, D-045).
- `inject` writes to stdout only and refuses a regular file.
- Live demo, or the recorded one.

## 5. Agent and audit log (3 min)

- The agent holds the key behind a Unix socket, checks the caller's UID in both directions, and wipes the key on lock and idle timeout (C9).
- The audit log is hash-chained and authenticated; an anchor catches a rollback of log and head together (C8, R3).
- Show: one flipped byte and `audit verify` naming the record.

## 6. How it was tested (3 min)

- The ten invariants, each a test file in `tests/invariants/`, and the fuzz targets for every parser (C10).
- The campaign: where its numbers come from (`scripts/numbers.sh`), and how many crashes it found.
- The postmortem (`docs/postmortem.md`): a security claim about a dependency that was wrong twice, and what it changed.
- Where Claude Code built the code, under a written plan and per-phase review, and what the owner verified.

## 7. Limits and questions (2 min)

- What vaultline doesn't protect: a weak passphrase (R1), metadata (R2), replacing the vault with an older valid copy (R3), what a child does with a secret (R6, R7).
- Questions to be ready for: why those Argon2id parameters; why bind the item ID; how the agent authenticates callers; what happens to a secret in a child's memory after it exits.
