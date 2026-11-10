# Project 4: Rust secrets-injection CLI

A Rust CLI that keeps secrets in an encrypted local vault and injects them into child processes or templates without writing plaintext to disk. Keys are layered: Argon2id derives a key from the passphrase, which unlocks a master key, which unlocks per-item keys. Items use XChaCha20-Poly1305 with the format version, vault ID and item ID as associated data, and an HMAC covers the whole vault file (`docs/decisions.md` D-003). It includes an agent behind a Unix socket and a hash-chained audit log.

## Source of truth

- Until the Phase 0 PR is merged, `PLAN.md` is the brief.
- After that, the docs are the source of truth: `docs/requirements.md`, `docs/architecture.md`, `docs/design.md`, `docs/threat-model.md`, `docs/vault-format.md`, `docs/decisions.md` and `docs/phases.md`. If code and docs disagree, the docs win. If the docs look wrong, stop and ask me.

## Workflow: one phase, one PR

I start every phase by name ("Start phase 3"). Never start a phase on your own.

1. **Sync.** `git checkout main && git pull`. Check with `gh pr list` that no earlier phase PR is still open. Create the branch `phase-<N>-<short-name>`.
2. **Read.** Read the phase in `docs/phases.md` and the docs it touches. If anything is ambiguous, missing or conflicts with the docs, ask me before writing code. Never invent requirements.
3. **Build the whole phase.** Write the code, a test for every acceptance criterion, and any doc updates the phase lists. Use small, logical commits with clear messages.
4. **Verify.** `make lint` and `make test` must pass locally. cargo-deny, cargo-audit and the fuzz smoke run happen only in CI, so push the branch and make sure the CI Linux job passes before opening the PR (`docs/decisions.md` D-022). Any check the phase names must pass too. Never skip, weaken or delete a test to get green; if a test is wrong, say so in the PR.
5. **Self-review.** Review `git diff main...HEAD` as a senior security engineer would. Check secret handling, crypto misuse, panics on untrusted input, a test for each behaviour, and needless complexity. Fix what you find.
6. **Open the PR.** Push, then run `gh pr create` and fill in every section of `.github/pull_request_template.md`.
7. **Stop.** Send me the PR link and wait.

**When I ask you to address review comments,** read them with `gh pr view <n> --comments` and `gh api repos/{owner}/{repo}/pulls/<n>/comments`. Fix them on the same branch, run lint and tests, push, and reply with a list of what changed. Never merge.

## Phase 0 is planning only

Write no code and do no scaffolding. First ask me every open question: start with "Questions Phase 0 must settle" in PLAN.md, then add anything else unclear. Ask in batches of up to 5, each with options, trade-offs and your recommendation. Record every question and answer in `docs/decisions.md`. Only when nothing is open, write the Phase 0 docs listed in PLAN.md. Self-review them for gaps, contradictions and untestable criteria, then open a docs-only PR.

## Surprises mid-phase

If the design turns out to be wrong or a requirement can't be met, stop. Explain the problem and the options, then wait. Once I decide, record the decision in `docs/decisions.md` and continue. Out-of-scope ideas go under "Follow-ups" in the PR, not into the code.

## Hard limits

- Never push to `main`, merge a PR, force-push, or rewrite pushed history.
- I am the only author. Commits and PRs carry no `Co-Authored-By` trailer, no "Generated with Claude Code" line and no mention of Claude or AI in commit messages, PR titles or PR bodies.
- Free and local only. Use no cloud services, no paid APIs, no sign-ups, and no credentials. If something seems to need one, stop and ask.
- No real secrets anywhere in the repo, tests or fixtures. Use obviously fake values.
- Never install anything on this Mac: no `brew`, no `cargo install`, no new `rustup` toolchains or components, no `curl | sh`, no installers. Crates through Cargo are fine. If a tool is missing, stop and ask me.
- Add only well-known, widely used crates, pinned in the committed `Cargo.lock`. Justify each new one in the PR.
- Never download or run an AI model. Nothing keeps running after a command finishes: tests stop every vault agent they start.
- Never fuzz on this Mac for more than a few minutes. `make fuzz` is a short smoke run; the long campaign runs only in the `fuzz-campaign` GitHub Actions workflow, which I start myself.
- Change `docs/requirements.md`, `docs/architecture.md`, `docs/design.md`, `docs/threat-model.md` or `docs/vault-format.md` only with my approval, and log each change in `docs/decisions.md`.
- Never put a number in `README.md` or `docs/` unless a script in the repo produced it.

## Project rules

- Never implement a cipher, KDF, MAC or random number generator. Use the RustCrypto crates named in the docs.
- Keep `#![forbid(unsafe_code)]` at the crate root.
- Types that hold secrets use `secrecy`/`zeroize` and never derive or implement Debug or Display. Error messages and logs never contain secret values.
- Never use `unwrap`, `expect` or indexing on untrusted input: vault bytes, references, templates, socket messages.
- The v1 vaults in `tests/fixtures/` are known-answer tests. Once the phase 2 PR is merged, never regenerate or edit them; a format change gets a new version and new fixtures.
- In CI, run the Linux job on every push and the macOS job on pull requests only. macOS runners use up a private repo's free minutes much faster.
- The shell-plugin side quest happens only in my fork of 1Password/shell-plugins. Never open a PR or issue on 1Password's repo; I submit it myself.

## Stack and commands

- Rust stable (nightly only for cargo-fuzz); `argon2`, `chacha20poly1305`, `zeroize`, `secrecy`, `clap`, `serde`, `nix`; `proptest`, `criterion`, `cargo-deny`, `cargo-audit`
- `make test` · `make lint` (fmt --check + clippy -D warnings) · `make audit` (deny + audit) · `make fuzz` (short smoke run) · `make bench` · fuzz campaign: the `fuzz-campaign` workflow on GitHub Actions (I start it with `gh workflow run fuzz-campaign.yml`)

## Invariants the tests must enforce

1. Seal then open returns the original bytes.
2. Any changed byte in the vault is rejected with a format or authentication error, never wrong plaintext or a panic (`docs/decisions.md` D-002).
3. An item's ciphertext moved to another item's slot fails to open.
4. A wrong passphrase gives a clean error.
5. Format v1 fixtures always open with their known plaintexts.
6. run and inject never write secret values to the filesystem.
7. Secrets never appear in captured child output, even across chunk boundaries.
8. Any edit, deletion or reordering of audit entries is detected.
9. The agent refuses other UIDs and forgets the key after lock or idle timeout.
10. No parser panics on any input.
