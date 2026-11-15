# Demo script: 3 minutes

A shot-by-shot script for the demo video of `run`, `inject`, masking and tamper detection (P5-5, D-029). The owner records it. Every output below was captured from the built binary in a throwaway directory with fake values, so the video should show the same text.

## Before recording

- **Use fake values only.** The passphrase is `fake-demo-passphrase-123` and the secret is `fake-db-password-1234`. No real secret appears on screen, in a file or in the shell history.
- **Use a clean directory and a short path.** The agent's socket path has a length limit (103 bytes on macOS), so the vault directory must have a short path:

  ```sh
  export VAULTLINE_DIR="${TMPDIR%/}/vd-demo/vl"
  mkdir -p "${TMPDIR%/}/vd-demo" && cd "${TMPDIR%/}/vd-demo"
  printf 'password={{ vault://demo/db/password }}\n' > db.tpl
  ```

- **Build once:** `cargo build --release`, and put `target/release` on the `PATH` for the recording. Run `clear` before the first shot.
- **Terminal:** 100 columns, large font, no prompt decoration. Type at a steady pace; shots are timed to the second, so rehearse once.
- **Afterwards:** `vaultline agent stop`, so no agent keeps running, then delete the demo directory.

## Shots

| Shot | Starts | Length | On screen | Say |
|---|---|---|---|---|
| 1 | 0:00 | 15 s | Title card: "vaultline: secrets in, no plaintext on disk". | "Developers keep secrets in .env files and shell history. vaultline keeps them in an encrypted vault and hands them to a program only while it runs." |
| 2 | 0:15 | 30 s | `vaultline init`, then `vaultline set vault://demo/db/password`, typing the passphrase and the value at the hidden prompts. Then `vaultline list`, then `strings "$VAULTLINE_DIR/vault" \| head -3`. | "Init creates the vault. Set reads the value from a hidden prompt, never from an argument. List shows names, never values. And the file on disk is ciphertext: strings finds nothing readable except the format's magic bytes." |
| 3 | 0:45 | 25 s | `vaultline unlock`, which prints `unlocked; the agent forgets the key after 900 idle seconds`. | "Unlock starts a small agent that holds the key behind a Unix socket, for the current user only. It wipes the key after fifteen idle minutes, or on lock." |
| 4 | 1:10 | 35 s | `DB_PASSWORD=vault://demo/db/password vaultline run -- sh -c 'echo "connecting with $DB_PASSWORD"'` prints `connecting with <concealed by vaultline>`. Then the same with `--no-mask`: a warning, then `connecting with fake-db-password-1234`. | "Run replaces the reference with the secret in the child's environment. The child can use it, but if it prints it, vaultline masks the output, even when the secret is split across chunks. With no-mask the child's output is untouched, and vaultline warns." |
| 5 | 1:45 | 30 s | `vaultline inject -i db.tpl` prints `password=fake-db-password-1234`. Then `vaultline inject -i db.tpl > out.txt`: refused, with `standard output is a regular file, so secrets would be written to disk`. Show `ls -l out.txt`: 0 bytes. | "Inject renders a template to standard output only, so a pipe can feed the program that needs it. Redirecting to a file is refused, and the file stays empty." |
| 6 | 2:15 | 35 s | `vaultline audit verify` prints `audit log verified: N records, the head covers N`. Then flip one byte of `audit.log` with `printf '\xff' \| dd of="$VAULTLINE_DIR/audit.log" bs=1 seek=100 count=1 conv=notrunc`, and run `audit verify` again: `audit verification failed: record 0: its MAC is wrong`. | "Every use is recorded in a hash-chained, authenticated log. Change one byte, and verify says exactly which record is wrong. The vault file is the same: one changed byte fails its MAC and never decrypts to wrong data." |
| 7 | 2:50 | 10 s | `vaultline agent stop` prints `the agent stopped`. End card: the repository name and "docs/threat-model.md: what it protects, and what it doesn't". | "Stop wipes the key and ends the agent. The threat model says what vaultline protects, and what it doesn't: malware running as you can still ask the agent." |

The tamper in shot 6 is done on the demo vault's own log after the earlier shots, so do it last. If the vault file's tamper is wanted on screen as well, do it on a copy of the directory made with `mkdir -m 700` and `cp` of the files, never of the agent's socket. The message is `the vault failed authentication: the file MAC does not match`.

## What the video must not claim

- That masking is a security boundary. It catches accidents in a child's stdout and stderr; it doesn't stop a child that encodes or sends a secret elsewhere (`docs/threat-model.md` R7).
- That vaultline protects against malware running as the user, or against root (T7, T8).
- Any number. If a number is wanted, it comes from `scripts/numbers.sh` and the README names it (D-006).
