# Architecture

How vaultline is put together: the key hierarchy, the components, the main sequences and where everything lives on disk. The byte-level formats are in `vault-format.md`, behaviour and invariants in `design.md`, and the reasons for each choice in `decisions.md`.

## 1. Key hierarchy

```mermaid
flowchart TD
    P["Passphrase<br/>prompt or --passphrase-stdin"] --> A["Argon2id<br/>256 MiB, t=3, p=4 by default"]
    S["kdf_salt and parameters<br/>from the vault header"] --> A
    A --> KEK["KEK<br/>never stored, wiped after use"]
    KEK -- "XChaCha20-Poly1305<br/>AAD: label + header bytes 0..54" --> MK["Master key<br/>in memory only while unlocked"]
    MK --> H["HKDF-SHA-256<br/>salt = vault_id"]
    H -- "info: vaultline v1 wrap" --> KW["K_wrap"]
    H -- "info: vaultline v1 file-mac" --> KM["K_mac"]
    KM -- "HMAC-SHA-256" --> FM["file_mac<br/>covers every byte of the vault"]
    KW -- "XChaCha20-Poly1305<br/>AAD: label + version + vault_id" --> AK["Audit key<br/>kept through rotate"]
    KW -- "XChaCha20-Poly1305<br/>AAD: label + version + vault_id + item_id" --> IK["Item key<br/>one per item"]
    IK -- "XChaCha20-Poly1305<br/>AAD: label + version + vault_id + item_id" --> IT["Item payload<br/>project, item name, fields"]
    AK -- "HMAC-SHA-256" --> AL["Audit records and head"]
```

| Operation | Changes | Leaves alone |
|---|---|---|
| `passwd` | salt, KEK, the wrap of the master key | master key, audit key, item keys, item ciphertext |
| `rotate` | salt, KEK, master key, every item key, every item ciphertext (fresh nonces) | `vault_id`, every `item_id`, the audit key (re-wrapped under the new master key) |

(D-004, D-034)

## 2. Components

```mermaid
flowchart LR
    T["Terminal"]
    subgraph CLI["vaultline (one process per command)"]
        C["Commands<br/>clap"]
        PR["Parsers<br/>reference, env file, template"]
        M["Masker"]
        CO["Vault core<br/>format and crypto"]
        AC["Agent client<br/>checks the agent's UID"]
        AW["Audit writer"]
    end
    subgraph AG["vaultline agent serve (optional, background)"]
        SV["Socket server<br/>checks caller UID, idle timer"]
        CO2["Vault core<br/>holds the master key"]
        AW2["Audit writer"]
    end
    subgraph FS["Vault dir: ~/.vaultline or VAULTLINE_DIR, mode 0700"]
        V["vault"]
        L["audit.log, audit.head"]
        UF["unlock-failures"]
        LK["lock, agent.lock"]
        SO["agent.sock"]
    end
    CH["Child process<br/>under vaultline run"]
    T <--> C
    C --> PR
    C --> AC
    AC <-->|"Unix socket"| SO
    SO <--> SV
    SV --> CO2
    CO2 --> V
    AW2 --> L
    C --> CO
    CO --> V
    AW --> L
    C -- "environment with resolved values" --> CH
    CH -- "stdout and stderr pipes" --> M
    M -- "masked bytes" --> T
```

- **Commands** decide where each request goes. If an agent is reachable and passes the UID check, the request goes to the agent. Otherwise the command prompts for the passphrase and does the work in-process, and the key is wiped when the command exits (D-014).
- **The vault core** is the same library code in both paths: it encodes and decodes the vault format, derives keys, and seals and opens items.
- **The agent** holds the master key and decrypts on request. It returns only the field values asked for, and the master key never leaves its process (D-014).
- **The masker** sits between the child's output pipes and the terminal (D-007, D-009).
- **Audit writers** append records under the writer lock, whichever process is doing the work (D-015, D-016, D-030).

### Where a command's request goes

```mermaid
flowchart TD
    A["Command needs vault access"] --> B{"agent.sock exists and<br/>the agent's UID matches mine?"}
    B -- "yes" --> C{"Agent unlocked?"}
    C -- "yes" --> D["Send the request to the agent"]
    C -- "no, locked" --> F
    B -- "no agent" --> F["Prompt for the passphrase<br/>or read --passphrase-stdin"]
    F --> G["Unlock in-process, do the work,<br/>wipe keys on exit"]
    B -- "UID mismatch or bad directory" --> H["Refuse with an error"]
```

A locked agent stays locked. The command does its own work in-process, and the agent's state doesn't change. `init`, `passwd` and `rotate` always run in-process and always ask for the current passphrase, even when an agent is unlocked, so nobody at an unlocked terminal can change the keys. After `rotate`, the command tells a running agent to lock, because the agent's master key is now out of date. `passwd` doesn't change the master key, so the agent keeps working.

## 3. `vaultline run` through the agent

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant C as vaultline run
    participant A as Agent
    participant F as Vault dir
    participant P as Child process
    U->>C: vaultline run --env-file .env.tpl -- npm start
    C->>C: Collect vault:// references from the environment and the env file, check syntax
    C->>F: Check directory owner and mode
    C->>A: Connect to agent.sock
    A->>A: Caller UID equals own UID, else close before reading
    C->>C: Agent UID equals own UID, else abort
    C->>A: Resolve(references)
    A->>F: Read vault, verify file_mac
    A->>A: Decrypt the needed items, reset idle timer
    A->>F: Append a read record for each item (writer lock)
    A-->>C: All values, or one error and nothing else
    C->>C: Build the masker, warn about values shorter than 8 bytes
    C->>P: Spawn: environment set, stdout and stderr piped, stdin inherited
    loop until both pipes close
        P-->>C: Output chunk
        C-->>U: Masked bytes, holding back only a possible secret prefix
    end
    P-->>C: Exit status
    C->>C: Flush the masker, wipe values
    C-->>U: Exit with the child's code, or 128 + signal
```

Without an agent, steps 4 to 10 are replaced by an in-process unlock: Argon2id, unwrapping the master key, verifying the file MAC and decrypting the items, with the `unlock` and `read` records appended directly.

## 4. Unlocking and starting the agent

```mermaid
sequenceDiagram
    actor U as User
    participant C as vaultline unlock
    participant A as vaultline agent serve
    participant F as Vault dir
    U->>C: vaultline unlock
    C->>F: Is an agent reachable on agent.sock?
    alt agent running and locked
        C->>A: Unlock(passphrase) over the socket
    else agent running and unlocked
        C-->>U: Already unlocked
    else no agent
        C->>A: Spawn the same binary, own process group, stdio piped
        C->>A: Passphrase on stdin, then close stdin
        A->>F: Take agent.lock, or exit if another agent holds it
        A->>A: Core-dump limit 0, non-dumpable on Linux
    end
    A->>F: Read vault, run Argon2id, unwrap the master key, verify file_mac
    A->>F: Append unlock record, plus a failed-unlocks record if the counter is above 0
    A->>F: Bind agent.sock with umask 077
    A-->>C: One status byte: ready, or an error code
    C-->>U: Unlocked, or the error
```

The passphrase never appears in the agent's arguments or environment (D-012, D-014). The agent ignores SIGHUP. Ctrl-C in the terminal doesn't reach it, because it runs in its own process group. It wipes the master key on `vaultline lock`, on `vaultline agent stop`, on SIGTERM or SIGINT sent to it directly, and after the idle timeout, which is 15 minutes by default (D-013). On idle timeout or stop, it also removes `agent.sock` and exits.

## 5. Vault file layout

```mermaid
flowchart LR
    subgraph HD["Header: bytes 0 to 202"]
        direction TB
        h1["magic, format_version, vault_id"]
        h2["kdf_m_kib, kdf_t, kdf_p, kdf_salt"]
        h3["mk_nonce, mk_box"]
        h4["ak_nonce, ak_box"]
        h5["item_count"]
    end
    subgraph RC["Item records, ascending item_id"]
        direction TB
        r1["item_id, ik_nonce, ik_box,<br/>payload_nonce, payload_len, payload_box"]
        r2["... one per item"]
    end
    MAC["file_mac<br/>last 32 bytes"]
    HD --> RC --> MAC
```

| Region | Encrypted | Authenticated by |
|---|---|---|
| magic, version, `vault_id`, KDF parameters, salt | no | the associated data of `mk_box`, and `file_mac` |
| `mk_box` | yes, under the KEK | its AEAD tag |
| `ak_box`, `ik_box` | yes, under `K_wrap` | their AEAD tags, and `file_mac` |
| `item_count`, record framing | no | `file_mac` |
| `payload_box`: names and values | yes, under the item key | its AEAD tag, and `file_mac` |

## 6. Audit chain

```mermaid
flowchart LR
    HDR["Log header<br/>magic, version, vault_id"] -- "SHA-256" --> R0["Record 0"]
    R0 -- "SHA-256" --> R1["Record 1"]
    R1 -- "SHA-256" --> RN["Record n-1"]
    RN -. "count and last_hash" .-> HEAD["audit.head<br/>MAC under the audit key"]
    HEAD -. "vaultline audit head" .-> ANC["Anchor kept elsewhere<br/>count:hash"]
```

Each record holds the SHA-256 of the record before it and an HMAC under the audit key. The head records how many entries exist, and an anchor saved outside the vault catches a rollback of the log and head together (D-015).

## 7. Files and directories

| Path, under `~/.vaultline` or `$VAULTLINE_DIR` | Mode | Holds | Written by |
|---|---|---|---|
| directory | 0700 | everything below; owner and mode checked before every use | `init` |
| `vault` | 0600 | the vault (`vault-format.md` §4) | `init`, `set`, `rm`, `passwd`, `rotate` |
| `audit.log` | 0600 | audit records (§5.1–5.3) | any command that unlocks, reads or writes, and the agent |
| `audit.head` | 0600 | audit head (§5.4) | the same |
| `unlock-failures` | 0600 | unauthenticated count of failed unlocks (§5.5) | failed unlocks |
| `lock` | 0600 | empty; held with `flock` while writing | every writer |
| `agent.lock` | 0600 | empty; held with `flock` for as long as an agent runs | the agent |
| `agent.sock` | socket | the agent's endpoint | the agent |
| `.vault.tmp-*`, `.audit.head.tmp-*` | 0600 | ciphertext only, during an atomic replace | writers |

Nothing outside this directory is ever written. Plaintext secrets go only to the child's environment (`run`) or to stdout (`get`, `inject`), and stdout is refused when it is a regular file (D-010, D-011).

## 8. Source layout (created in Phase 1)

```
src/
  main.rs         clap command tree, exit codes
  lib.rs          #![forbid(unsafe_code)], modules
  paths.rs        VAULTLINE_DIR, directory owner and mode checks
  hardening.rs    core-dump limit, non-dumpable on Linux
  secret.rs       secret wrapper types (no Debug or Display)
  vault/
    mod.rs        create, open, set, rm, list, passwd, rotate
    format.rs     v1 encoder and decoder
    crypto.rs     Argon2id, HKDF, AEAD, file MAC
    store.rs      atomic replace, writer lock
  inject/
    reference.rs  vault://project/item/field parser
    envfile.rs    --env-file parser
    template.rs   {{ vault://... }} parser and renderer
    mask.rs       streaming masker
    run.rs        child process, pipes, signals
    output.rs     refusal when stdout is a regular file
  agent/
    protocol.rs   frame encoder and decoder
    server.rs     socket, peer check, idle timer
    client.rs     connect, peer check, requests
  audit.rs        records, head, append, verify, anchors
tests/
  invariants/     one file per invariant, s1_*.rs to s10_*.rs
  adversarial/    tamper, swap, truncation, socket and filesystem attacks
  fixtures/v1/    known-answer vaults (vault-format.md §7)
fuzz/             cargo-fuzz crate, outside the workspace
  fuzz_targets/   vault_file, reference, template, agent_message
benches/          criterion: unlock, run overhead
scripts/          scripts that produce every published number
```
