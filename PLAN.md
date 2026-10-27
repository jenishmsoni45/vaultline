# Project 4: Rust secrets-injection CLI

> A developer tool that keeps secrets in an encrypted local vault and injects them into a process at run time, so they never sit in plaintext `.env` files. It ships with a written threat model, tamper tests and fuzzing.

| | |
|---|---|
| **Wave** | Wave 1 |
| **Dates** | Phase 0 before Jan 4 · build Jan 4–31. If 1Password's posting opens before Shopify's, build this before project 3. |
| **Built for** | 1Password (Client Secrets, Data Security, Ecosystems teams), then security and developer-platform teams at Stripe, Google, Amex and Capital One |
| **Stack** | Rust (stable; nightly only for cargo-fuzz), RustCrypto (`argon2`, `chacha20poly1305`), `zeroize`, `secrecy`, `clap`, `serde`, `nix`, `proptest`, `criterion`, `cargo-fuzz`, `cargo-deny`, `cargo-audit` |
| **Install** | rustup (stable and nightly), cargo-fuzz, cargo-deny, cargo-audit, git, gh |
| **Cost** | Free. The optional shell-plugin contribution happens only if it needs no paid account. |

---

## 1. What you're building

1Password's Client Secrets interns work on the 1Password CLI, SSH agent and developer workflows, and their Data Security team writes Rust and Go. This tool is a small cousin of their CLI. Be upfront about that: the design reasoning is what you're showing.

What makes it stand out:
- **No home-made crypto.** It uses audited RustCrypto crates; the work is choosing, composing and justifying them.
- **A real threat model:** what it protects against, what it doesn't, and why.
- **Evidence, not claims:** tamper tests, known-answer tests and fuzzing hours.

## 2. Scope

**In**
- An encrypted vault with layered keys. Argon2id turns the passphrase into a key that unlocks a master key, and the master key unlocks a key for each item. Items use XChaCha20-Poly1305 with the item's ID bound as associated data. The format is versioned and supports key rotation.
- `vault run -- <command>`: secrets go only into the child's environment and are masked in its output.
- `vault inject`: resolves `vault://project/item/field` references in a template and writes to stdout, never to disk.
- An agent holding the unlocked key behind a Unix socket, with a caller-identity check and an idle timeout.
- A hash-chained audit log with `vault audit verify`.
- A threat model, known-answer tests, property tests, fuzzing (the long campaign runs on GitHub Actions, not your Mac), and cargo-deny and cargo-audit in CI on Linux and macOS.

**Optional side quest:** one shell plugin for 1Password's open-source `shell-plugins` repo (Go), only if it needs no paid account.

**Out of scope:** sharing secrets between teammates, Touch ID or Keychain unlock, a GUI, syncing, implementing any cipher or KDF, and any cloud or paid service.

## 3. Architecture (starting sketch; Phase 0 turns it into Mermaid diagrams)

```
passphrase ──Argon2id(salt, params)──▶ KEK ──unwraps──▶ master key ──unwraps──▶ item key ──XChaCha20-Poly1305──▶ item
                                                         (held by the agent,               AAD = vault id ‖ item id ‖ format version
                                                          zeroized on lock/timeout)

vault run -- npm start                                vault inject -i config.tpl
   │ resolve refs via agent ─┐                           │ resolve refs via agent
   ▼                         ▼                           ▼
 child process env     agent (Unix socket, 0700 dir,    stdout only
 stdout/stderr ──▶     peer UID check, idle timeout)
 masking filter ──▶ terminal

every unlock / read / write ──▶ audit log: entry_n = { event, time, prev_hash, HMAC }
```

**Threat model, starting point:**
- **In scope:** a stolen laptop disk or backup; a vault file leaked in a repo; secrets ending up in logs, shell history or `.env` files; other local users on the same machine.
- **Out of scope:** malware running as you, root, or someone reading the live memory of an unlocked agent. The threat model says why each is out.

## 4. Guarantees and numbers

| # | Invariant | How it's tested |
|---|---|---|
| S1 | Opening a sealed item returns exactly the original bytes. | proptest round trip |
| S2 | Any changed byte of the vault gives an authentication error, never wrong plaintext or a panic. | proptest flipping random bytes, plus fuzzing |
| S3 | An item's ciphertext moved into another item's slot fails to open. | Swap test |
| S4 | A wrong passphrase gives a clean error. | Unit test |
| S5 | Vaults written by format v1 open forever with their known plaintexts. | Known-answer fixtures |
| S6 | `run` and `inject` never write a secret to the filesystem. | Run in a temp HOME and scan every file written |
| S7 | A secret never appears in captured child output, even split across read chunks. | proptest with random chunk boundaries |
| S8 | Any edit, deletion or reordering of audit entries is detected. | Tamper tests |
| S9 | The agent refuses other UIDs, and forgets the key after lock or idle timeout. | Unit and integration tests |
| S10 | No parser panics on any input. | cargo-fuzz on the vault, reference and template parsers |

**Numbers to publish:** fuzzing CPU-hours, and crashes found and fixed; the Argon2id parameters and the unlock time they give, with the reason; `vault run` startup overhead; test counts.

## 5. Questions Phase 0 must settle

1. What Argon2id memory, iterations and parallelism, and what target unlock time? Why?
2. JSON with base64 or a binary format? How will a v2 migrate v1 vaults?
3. Exactly what goes into each item's associated data, and which attack does it stop?
4. What does a passphrase change re-encrypt, and what does a master-key rotation re-encrypt?
5. How does masking handle a secret split across output chunks, and very short secrets?
6. How does the agent identify the caller on Linux and on macOS? What's the idle timeout?
7. How does the audit log detect truncation, not just edits?
8. Does `inject` write only to stdout, or also to a named pipe?
9. Which OSes are supported: macOS and Linux only?
10. Shell-plugin side quest: yes or no? If yes, which CLI? (Building, validating and unit-testing a plugin uses `make` targets in the repo; skip the side quest if testing it would need a paid 1Password account.)
11. How long does the fuzz campaign run on GitHub Actions, split into how many jobs, and does it fit the free minutes (2,000 Linux minutes a month on a private repo, unlimited on a public one)?

## 6. Phases

Each phase is one PR. Phase 0 writes the full acceptance criteria into `docs/phases.md`; these are the seeds.

| Phase | Target dates | Scope | Done when | Look closely at |
|---|---|---|---|---|
| **0** Plan | Before Jan 4 | Questions answered; requirements, architecture (Mermaid), design, threat model, vault format, phases, decisions | No open questions; docs consistent | Threat model; key hierarchy; associated data |
| **1** Scaffold | Jan 4 | Cargo layout, clap command tree returning "not implemented", deny.toml, fuzz crate, Makefile, CI (Linux on push, macOS on PR) | CI green; `#![forbid(unsafe_code)]` in place | Dependency list; CI matrix |
| **2** Crypto core and format | Jan 5–10 | KDF, key wrapping, seal and open, format v1, fixtures | S1–S5 pass; v1 fixtures committed | Every line of the crypto wiring; nonce generation |
| **3** CLI, injection, masking | Jan 11–17 | init, set, get, list, rm, passwd, rotate; reference parser; run with masking; inject; fuzz targets | S6, S7 pass; fuzz targets run | Masking buffer; temp-file handling |
| **4** Agent and audit log | Jan 18–24 | Socket server and client, peer-UID check, idle timeout, zeroize on lock; hash chain and `audit verify` | S8, S9 pass | Peer check; truncation detection |
| **5** Harden and ship | Jan 25–31 | Fuzz-campaign workflow on GitHub Actions, benchmarks, README, threat-model polish, postmortem, talk outline | S10 holds after the campaign; definition of done met | Security claims vs tests |
| **Side quest** (optional) | Evenings in January | One shell plugin, built in your fork | You submit the PR to 1Password yourself after review | The repo's rules on AI-assisted contributions |

## 7. Repo layout (Phase 1 creates it)

```
project-4-rust-secrets-cli/
├── CLAUDE.md  PLAN.md  README.md  .github/pull_request_template.md
├── docs/        requirements.md  architecture.md  design.md  threat-model.md  vault-format.md  decisions.md  phases.md  postmortem.md
├── src/         main.rs  vault/  inject/  agent/  audit.rs
├── tests/       invariants/  adversarial/  fixtures/ (v1 vaults)
├── fuzz/        fuzz_targets/
├── benches/     criterion benchmarks; results in bench/results/
├── deny.toml  Makefile  .github/workflows/ci.yml  .github/workflows/fuzz-campaign.yml
```

## 8. Prompts

Run `claude` inside this folder. The workflow rules live in `CLAUDE.md`, so the prompts stay short.

### P0 · Phase 0: plan (paste once)

```text
Start phase 0 (planning). Follow the Phase 0 rules in @CLAUDE.md: no code and no scaffolding.
1. Read @PLAN.md. List every open question: start with section 5, then add anything ambiguous, missing or contradictory. Ask me in batches of up to 5, each with options, trade-offs and your recommendation. Wait for my answers before the next batch.
2. Record every question and answer in docs/decisions.md.
3. When nothing is open, write:
   - docs/requirements.md: users, user stories with acceptance criteria, non-functional requirements with numbers, non-goals
   - docs/architecture.md: Mermaid diagrams for the key hierarchy, the components, the `vault run` sequence through the agent, and the vault file layout
   - docs/threat-model.md: assets, adversaries, trust boundaries, in and out of scope with reasons, mitigations, residual risks
   - docs/vault-format.md: the byte-level v1 format, what is authenticated, and the versioning and migration rules
   - docs/design.md: invariants S1–S10, failure modes, alternatives rejected, prior art (1Password CLI, sops, age), test plan
   - docs/phases.md: phases 1–5 from PLAN.md section 6, each with scope, testable acceptance criteria, tests to add and out of scope
4. Review the docs as a skeptical application security engineer: crypto composition, secrets escaping (env, core dumps, logs, panics), socket races, and threat-model claims without a mechanism or test. Also flag anything that needs an install on this Mac beyond the Install row. Fix them, and ask me if a fix needs a decision.
5. Create branch phase-0-plan, commit, push, and open a docs-only PR with the template. Then stop.
```

### P1 · Start a phase (every phase after 0)

```text
Start phase <N>. Follow the phase workflow in @CLAUDE.md: sync main and confirm earlier phase PRs are merged, branch, read the phase in @docs/phases.md, ask me before coding if anything is unclear, build the whole phase with tests, run lint, tests and audit, self-review the full diff and fix what you find, then push and open the PR with the template. Stop when the PR is open.
```

### P2 · Address my review

```text
I've reviewed PR #<n>. Read every comment (`gh pr view <n> --comments` and the inline comments via `gh api repos/{owner}/{repo}/pulls/<n>/comments`). Fix each one on the same branch, or explain why you disagree. Run lint, tests and audit, push, and reply with a short list of comment → what changed. Don't merge.
```

### P3 · Explain a PR to me (while reviewing)

```text
Walk me through PR #<n> as if onboarding me to code I must defend in a security interview. Follow the review-guide order. For each file: what it does, why it's built this way, the alternative rejected, the attack it stops, and how the tests prove it. Point out every place a secret lives in memory and when it's zeroized. Then ask me 5 questions about it, one at a time, and correct what I get wrong. Don't change any code.
```

### P4 · Mock interview (after phase 5)

```text
Act as a security engineer interviewing me at 1Password. Interview me about this project for 30 minutes, one question at a time. Start with "walk me through the threat model", then go deep wherever my answer is vaguest: key hierarchy, associated data, Argon2id parameters, the agent, masking limits. Ask at least one question about Rust ownership in this code. Use @PLAN.md section 9 and @docs/decisions.md as a starting point and follow up on my answers. Don't give me answers. At the end, score clarity, depth and ownership out of 5, and list 3 topics to study.
```

### P-OSS · Shell-plugin side quest (optional)

```text
I've forked and cloned 1Password/shell-plugins at <path>, and I want a plugin for <CLI name>. Read CONTRIBUTING.md and two existing plugins for similar CLIs, and check whether the repo has rules on AI-assisted contributions. Build the plugin on a branch in my fork, following the repo's conventions, and run `make <plugin-name>/validate` and the plugin's tests. Don't open a PR or issue on 1Password's repo. When done, explain the plugin file by file so I can review it and submit the PR myself.
```

## 9. Finish line

**Definition of done** (after phase 5)
- [ ] Phase 0 docs merged and kept current, including the threat model and vault format
- [ ] S1–S9 run in CI (Linux on push, macOS on PRs); fuzz targets smoke-tested in CI
- [ ] `make bench` and the `fuzz-campaign` workflow reproduce every README number
- [ ] `docs/postmortem.md` on one real bug found during the build
- [ ] 3-minute demo video (run, inject, mask, tamper detection) + 20-minute talk outline
- [ ] README section on how Claude Code built it under your plan and review, and how you verified it
- [ ] If you did the side quest: the PR link in the README

**Resume line** (fill in from your own measurements):
> Built a Rust CLI that injects secrets from an Argon2id/XChaCha20-Poly1305 encrypted vault into child processes without plaintext on disk. Wrote a threat model, a hash-chained audit log and cargo-fuzz harnesses (N CPU-hours, M parser bugs fixed).

**Questions to be ready for**
- Why those Argon2id parameters?
- What does your tool not protect against?
- Why envelope encryption instead of one key?
- Why bind the item ID as associated data?
- How does the agent authenticate callers?
- What happens to secrets in a child process's memory after it exits?
