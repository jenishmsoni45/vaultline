# Vault format

This document defines the on-disk formats of vaultline v1, byte by byte: the vault file, the audit log, the audit head and the failed-unlock counter. It also says what is authenticated and how, and sets the rules for versioning and migration. It is normative: an implementation that disagrees with it is wrong. Decisions are referenced as D-NNN (see `decisions.md`).

## 1. Conventions

- All integers are unsigned and little-endian. `u16`, `u32` and `u64` are 2, 4 and 8 bytes.
- `‖` means byte concatenation. `x[a..b)` means bytes `a` up to but not including `b` of `x`.
- Labels are ASCII strings written in quotes, with no length prefix or terminator.
- `version` in an associated-data string means the two bytes `01 00`, which is format version 1 as a `u16`.
- **Format error**: the bytes don't follow this document. Examples are a bad magic value, an unknown version, an out-of-range field, a length that overruns the file, or bytes left over at the end.
- **Authentication error**: an AEAD tag or a MAC didn't verify. A failed master-key unwrap is the one case reported as "wrong passphrase, or the vault header was modified", because those two can't be told apart.
- Invariant S2 (D-002) states that every change to a vault file produces one of these two errors. It never produces different plaintext, and the parser never panics.

## 2. Primitives

| Purpose | Algorithm | Crate |
|---|---|---|
| Passphrase to key-encryption key (KEK) | Argon2id, version 0x13, 32-byte output | `argon2` |
| Wrapping keys and encrypting items | XChaCha20-Poly1305, 24-byte nonce, 16-byte tag appended | `chacha20poly1305` |
| Subkeys from the master key | HKDF-SHA-256 | `hkdf`, `sha2` |
| File MAC, audit MACs | HMAC-SHA-256, verified in constant time | `hmac`, `sha2` |
| Audit hash chain | SHA-256 | `sha2` |
| Keys, salts, nonces, IDs | OS CSPRNG | `getrandom` through `rand_core::OsRng` |

Every nonce is 24 fresh random bytes, generated for each encryption. No nonce is derived, counted or reused on purpose.

## 3. Keys

| Key | Size | Origin | Stored as |
|---|---|---|---|
| KEK | 32 | Argon2id(passphrase, `kdf_salt`, `kdf_m_kib`, `kdf_t`, `kdf_p`) | never stored |
| Master key (MK) | 32 | random at `init` and at every `rotate` | `mk_box`, encrypted under the KEK |
| `K_wrap` | 32 | HKDF-SHA-256(salt = `vault_id`, IKM = MK, info = `"vaultline v1 wrap"`) | never stored |
| `K_mac` | 32 | HKDF-SHA-256(salt = `vault_id`, IKM = MK, info = `"vaultline v1 file-mac"`) | never stored |
| Audit key (AK) | 32 | random at `init`; kept through `rotate` (D-034) | `ak_box`, encrypted under `K_wrap` |
| Item key (IK) | 32 | random per item, at creation and at every `rotate` | `ik_box`, encrypted under `K_wrap` |

The passphrase is passed to Argon2id exactly as entered. There is no Unicode normalisation and no trimming, except that the line terminator `\n` is removed when the passphrase comes from `--passphrase-stdin` (D-012, D-029). The same passphrase typed with different Unicode normalisation is a different passphrase.

## 4. Vault file

The file lives at `$VAULTLINE_DIR/vault`, or `~/.vaultline/vault` by default. Its mode is 0600 (D-025, D-027).

### 4.1 Layout

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 8 | `magic` | `76 61 75 6C 74 6C 6E 00` (`"vaultln"` followed by a NUL byte) |
| 8 | 2 | `format_version` | `1` |
| 10 | 16 | `vault_id` | random at `init`, never changes |
| 26 | 4 | `kdf_m_kib` | Argon2id memory in KiB; see 4.4 |
| 30 | 4 | `kdf_t` | Argon2id iterations; see 4.4 |
| 34 | 4 | `kdf_p` | Argon2id lanes; see 4.4 |
| 38 | 16 | `kdf_salt` | random; new at every `passwd` and `rotate` |
| 54 | 24 | `mk_nonce` | |
| 78 | 48 | `mk_box` | encrypted MK (32 bytes) followed by its tag (16) |
| 126 | 24 | `ak_nonce` | |
| 150 | 48 | `ak_box` | encrypted AK (32 bytes) followed by its tag (16) |
| 198 | 4 | `item_count` | number of item records |
| 202 | variable | item records | `item_count` records, laid out as in 4.2 |
| file length − 32 | 32 | `file_mac` | HMAC-SHA-256(`K_mac`, file[0 .. length − 32)) |

An empty vault is 234 bytes long.

### 4.2 Item record

| Offset in record | Size | Field | Rule |
|---|---|---|---|
| 0 | 16 | `item_id` | random at item creation; kept through `rotate` |
| 16 | 24 | `ik_nonce` | |
| 40 | 48 | `ik_box` | encrypted IK (32 bytes) followed by its tag (16) |
| 88 | 24 | `payload_nonce` | |
| 112 | 4 | `payload_len` | length of `payload_box`; at least 16 |
| 116 | `payload_len` | `payload_box` | encrypted payload followed by its tag (16) |

The smallest record is 132 bytes. Records are ordered by `item_id`, strictly ascending as bytes, so duplicate IDs are a format error.

### 4.3 Item payload (the plaintext inside `payload_box`)

| Size | Field | Rule |
|---|---|---|
| 1 | `project_len` | 1–64 |
| `project_len` | `project` | name rule, see below |
| 1 | `item_len` | 1–64 |
| `item_len` | `item` | name rule |
| 2 | `field_count` | at least 1 |

Then `field_count` fields follow, each laid out as:

| Size | Field | Rule |
|---|---|---|
| 1 | `name_len` | 1–64 |
| `name_len` | `name` | name rule |
| 4 | `value_len` | 0–65,536 (64 KiB) |
| `value_len` | `value` | arbitrary bytes |

- **Name rule:** every byte is in `A–Z a–z 0–9 . _ -`, and names are case-sensitive (D-027).
- **Field order:** fields are ordered by `name`, strictly ascending as bytes.
- **No leftovers:** no bytes may follow the last field.
- **Uniqueness:** the pair (`project`, `item`) is unique within a vault. Names are encrypted, so this can only be checked after decryption. A vault with two records for the same pair is rejected with a format error.

Project, item and field names exist only inside `payload_box`, so the file shows nobody without the passphrase what is stored (D-005).

### 4.4 Argon2id parameter bounds

| Parameter | Value written by `init`, `passwd` and `rotate` | Range the parser accepts |
|---|---|---|
| `kdf_m_kib` | 262,144 (256 MiB) | 8 × `kdf_p` to 1,048,576 (1 GiB) |
| `kdf_t` | 3 | 1–10 |
| `kdf_p` | 4 | 1–8 |

The parser checks these bounds before Argon2id runs, so a tampered header can't make an unlock allocate more than the ceiling. Values below the written defaults are accepted, because tests and two of the fixtures use cheap parameters (D-001). Opening such a vault prints a warning that suggests running `vaultline passwd`, which rewrites the header with the current defaults.

### 4.5 Associated data

| Ciphertext | Key | Associated data | Length of associated data |
|---|---|---|---|
| `mk_box` | KEK | `"vaultline v1 master-key"` ‖ file[0..54) | 77 |
| `ak_box` | `K_wrap` | `"vaultline v1 audit-key"` ‖ version ‖ `vault_id` | 40 |
| `ik_box` | `K_wrap` | `"vaultline v1 item-key"` ‖ version ‖ `vault_id` ‖ `item_id` | 55 |
| `payload_box` | IK | `"vaultline v1 item"` ‖ version ‖ `vault_id` ‖ `item_id` | 51 |

The four associated-data strings have different lengths, so none can equal another, even where two contexts share a key (`ak_box` and `ik_box` both use `K_wrap`).

### 4.6 What is authenticated, and by what

| Bytes | Protected by | What a change produces |
|---|---|---|
| `magic`, `format_version` | format check, then the `mk_box` associated data and `file_mac` | format error, or authentication error if the change still parses |
| `vault_id`, `kdf_*`, `kdf_salt` | `mk_box` associated data; the salt and parameters also feed the KEK | authentication error (reported as an unlock error), or format error if a parameter goes out of bounds |
| `mk_nonce`, `mk_box` | AEAD under the KEK | unlock error |
| `ak_nonce`, `ak_box` | `file_mac` (checked first), then AEAD | authentication error |
| `item_count` and every item record | `file_mac`, then a separate AEAD for each `ik_box` and `payload_box` | authentication error |
| `file_mac` | itself | authentication error |
| truncation or extension anywhere | `file_mac` covers every byte before it, at a fixed position from the end | authentication error, or format error if the file is shorter than 234 bytes |

Swapping item slots (S3) is also caught without the file MAC: each `ik_box` and `payload_box` binds its `item_id`.

### 4.7 How a vault is opened (normative order)

1. Check the file size. A file under 234 bytes or over 64 MiB is a format error, raised before the whole file is read (D-027).
2. Parse the first 54 bytes: `magic`, `format_version` and the Argon2id bounds. An unknown version gives "unsupported format version N".
3. Derive the KEK with Argon2id.
4. Decrypt `mk_box`. A failure gives the unlock error, "wrong passphrase, or the vault header was modified" (S4).
5. Derive `K_wrap` and `K_mac`. Check `file_mac` in constant time. A failure gives an authentication error.
6. Parse `item_count` and the records. `item_count` must not exceed (file length − 234) / 132, and that is checked before anything is allocated. Every length must fit inside the file, records must be in strictly ascending order, and the parse must end exactly at the start of `file_mac`.
7. Decrypt `ak_box`.
8. Decrypt each `ik_box` and `payload_box` only when needed, and parse the payload as in 4.3.

Secret buffers (KEK, MK, subkeys, AK, IKs, payloads) are wiped when they are dropped (D-017).

### 4.8 How a vault is written

- The encoding is canonical: records are in ascending `item_id` order, fields in ascending `name` order, and there are no optional fields.
- Anything encrypted again gets a fresh nonce. Records that didn't change may keep their old bytes.
- **`set`** on an existing item decrypts its payload, changes the field, and encrypts it again under the same IK with a fresh nonce. A new item gets a new `item_id` and a new IK.
- **`rm`** removes a field. If that leaves the item with no fields, the whole record is removed (D-028).
- **`passwd`** generates a new `kdf_salt`, writes the default parameters, derives a new KEK and re-wraps the same MK. `ak_box` and all records are unchanged, and `file_mac` is recomputed (D-004).
- **`rotate`** generates a new `kdf_salt`, writes the default parameters, and creates a new MK. It re-wraps the same AK, gives every item a new IK, and encrypts every payload again with fresh nonces. `vault_id` and every `item_id` stay the same (D-004, D-034).
- **Every write** happens under the writer lock and replaces the file atomically. The new contents go to a temporary file in the same directory, which is flushed to disk and then renamed over the vault. The temporary file only ever holds ciphertext (D-027).

## 5. Audit log

The log lives at `$VAULTLINE_DIR/audit.log`, mode 0600. It is append-only, made of fixed-size records with no length fields (D-015, D-016, D-030, D-034).

### 5.1 File header (26 bytes)

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 8 | `magic` | `76 6C 61 75 64 69 74 00` (`"vlaudit"` followed by a NUL byte) |
| 8 | 2 | `audit_version` | `1` |
| 10 | 16 | `vault_id` | must equal the vault's `vault_id` |

### 5.2 Record (105 bytes)

| Offset in record | Size | Field | Rule |
|---|---|---|---|
| 0 | 8 | `seq` | 0 for the first record, then +1 each time |
| 8 | 8 | `time` | Unix seconds from the system clock; for information only, never trusted |
| 16 | 1 | `event` | see 5.3 |
| 17 | 16 | `item_id` | the item concerned, or all zeros |
| 33 | 8 | `detail` | depends on the event (5.3) |
| 41 | 32 | `prev_hash` | SHA-256 of the file header for `seq` 0; otherwise SHA-256 of the whole previous record |
| 73 | 32 | `mac` | HMAC-SHA-256(AK, `"vaultline v1 audit-record"` ‖ record[0..73)) |

### 5.3 Events

| Code | Event | `item_id` | `detail` |
|---|---|---|---|
| 1 | `init` | zero | 0 |
| 2 | `unlock` | zero | 0 = unlocked inside a command, 1 = unlocked by the agent |
| 3 | `lock` | zero | 0 = `vaultline lock`, 1 = agent stopped |
| 4 | `idle-timeout` | zero | 0 |
| 5 | `failed-unlocks` | zero | failed attempts since the last good unlock, read from the unauthenticated counter (5.5); `u64::MAX` means the counter couldn't be read |
| 6 | `read` | item | 0 |
| 7 | `set` | item | 0 |
| 8 | `rm` | item | 0 = a field was removed, 1 = the whole item was removed |
| 9 | `passwd` | zero | 0 |
| 10 | `rotate` | zero | 0 |
| 11 | `verify` | zero | 0 = passed, 1 = failed |

Any other code is a format error in audit format 1. Adding an event means a new `audit_version`. Records never hold secret values, names or the passphrase (D-016).

### 5.4 Head (`$VAULTLINE_DIR/audit.head`, 98 bytes)

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 8 | `magic` | `76 6C 61 68 65 61 64 00` (`"vlahead"` followed by a NUL byte) |
| 8 | 2 | `audit_version` | `1` |
| 10 | 16 | `vault_id` | must equal the vault's `vault_id` |
| 26 | 8 | `count` | number of records covered |
| 34 | 32 | `last_hash` | SHA-256 of record `count − 1`, or SHA-256 of the file header if `count` is 0 |
| 66 | 32 | `mac` | HMAC-SHA-256(AK, `"vaultline v1 audit-head"` ‖ head[0..66)) |

Appending works like this, all while holding the writer lock:

1. Write the new record at the end of the log and flush it to disk.
2. Replace the head atomically, the same way the vault file is replaced.

A crash between those steps leaves the log one record ahead of the head, which is not an error (5.6).

An **anchor** is the text `<count>:<last_hash in lowercase hex>`. `vaultline audit head` prints the current anchor after checking the head's MAC.

### 5.5 Failed-unlock counter (`$VAULTLINE_DIR/unlock-failures`)

- **Contents:** exactly 8 bytes, a single `u64` count. The file is not authenticated, because no key exists before an unlock succeeds. A missing file means 0. A file of any other length counts as unreadable.
- **On a failed unlock:** the count goes up by one, under the writer lock.
- **On the next successful unlock:** if the count isn't 0, a `failed-unlocks` record is appended and the counter is reset to 0.
- **Known risk:** anyone with write access to the directory can change or delete the counter. The threat model lists this.

### 5.6 What `vaultline audit verify` checks

The command needs an unlock, either directly or through the agent. It passes only if all of these hold:

1. The header's magic and version are valid, and its `vault_id` equals the vault's.
2. The log's length is 26 + n × 105 for some n. Anything else means a cut through the middle of a record.
3. Every record i has `seq` = i, a `prev_hash` that matches, a valid `mac` and a known `event`.
4. The head's magic, version and `vault_id` are valid, and its `mac` verifies.
5. The head's `count` is at most n. If it's greater, the log was truncated. Record `count − 1` hashes to `last_hash`, or the header does if `count` is 0.
6. With `--expect <c>:<h>`: c is at most n, and record c − 1 hashes to h (or the header does, if c is 0).

A missing head file fails check 4. Each run appends a `verify` record with the result (D-030).

## 6. Versioning and migration (D-002)

1. `format_version` and `audit_version` each name a complete layout, together with its algorithms, labels and bounds. Any change that makes a valid file invalid, or an invalid file valid, needs a new version number.
2. Readers keep the decoder for every version that was ever released, so a v1 vault opens for good (S5).
3. Writers write only the newest version.
4. A version this binary doesn't know gives "unsupported format version N; a newer vaultline wrote this file". The reader never guesses.
5. Upgrading needs an explicit `vaultline migrate`, which is built only once v2 exists (D-029). Nothing upgrades silently. `migrate` decrypts in memory and writes the new version with the atomic replace in 4.8.
6. The v1 known-answer fixtures in `tests/fixtures/v1/` are committed in Phase 2. After the Phase 2 PR merges, they are never edited or regenerated. A format change gets a new version and new fixtures next to the old ones.

## 7. v1 fixtures (created in Phase 2)

| File | Argon2id parameters | Contents |
|---|---|---|
| `empty.vault` | cheap | no items |
| `basic.vault` | cheap | two projects and several items. Includes an empty value, a 64 KiB value, names that use every allowed character class, and an item with many fields |
| `default-params.vault` | the defaults in 4.4 | one item |

`tests/fixtures/v1/README.md` lists each fixture's fake passphrase and its expected plaintext. Every value is obviously fake, for example `fake-stripe-key-not-real`.
