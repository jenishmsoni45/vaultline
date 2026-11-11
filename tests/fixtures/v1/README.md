# v1 known-answer fixtures

These vaults are the known-answer tests for vault format v1 (S5). `examples/generate_v1_fixtures.rs` wrote them once, from the blocks below, while the Phase 2 PR was being written. After that PR merges they are never edited or regenerated (`docs/vault-format.md` §6, rule 6). A format change gets a new version and new fixtures next to these.

Every passphrase and every value here is fake. None of them is, or ever was, a real secret.

## How the tests use this file

The blocks below are machine-read, so this file is the one place the contents are defined:

- `tests/invariants/s5_fixtures.rs` opens every fixture with its passphrase and checks its Argon2id parameters and that it holds exactly the fields listed, no more and no fewer (S5, P2-5). It also checks that every value listed is fake.
- `tests/adversarial/no_plaintext_in_vault.rs` checks that no name or value of 8 bytes or more appears in the fixture's bytes (P2-13, D-042).
- `tests/invariants/s2_tamper.rs` flips every byte of `basic.vault` and cuts it at every length (S2, P2-2).

Each block has:

- `fixture: <file name>`
- `passphrase: "<text>"`
- `kdf: m=<memory in KiB> t=<iterations> p=<lanes>`
- one line per field: `vault://<project>/<item>/<field> = <value>`, where `<value>` is one of:
  - `"<text>"`: the bytes between the quotes. They never contain a quote or a backslash.
  - `repeat("<pattern>", <n>)`: `<pattern>` repeated and cut to exactly `<n>` bytes.
  - `bytes(0..256)`: the 256 bytes 0x00 to 0xFF, in order.

## empty.vault

Cheap parameters and no items.

```text
fixture: empty.vault
passphrase: "fake-passphrase-empty-not-real"
kdf: m=8 t=1 p=1
```

## basic.vault

Cheap parameters, two projects and several items. It includes an empty value, a 64 KiB value, non-text bytes, names that use every allowed character class (one of them 64 bytes long, two of them 1 byte long), and an item with 40 fields.

```text
fixture: basic.vault
passphrase: "fake-passphrase-basic-not-real"
kdf: m=32 t=2 p=2
vault://acme-web/stripe/api_key = "fake-stripe-key-not-real"
vault://acme-web/stripe/webhook_secret = "fake-webhook-secret-not-real"
vault://acme-web/postgres/password = "fake-db-password-not-real"
vault://acme-web/postgres/user = "fake-db-user"
vault://acme-web/postgres/empty = ""
vault://acme-web/a/b = "fake-one-byte-names-not-real"
vault://Billing.Svc_2-x/blob/data_64k = repeat("fake-64k-", 65536)
vault://Billing.Svc_2-x/blob/binary = bytes(0..256)
vault://Billing.Svc_2-x/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678._-/all_classes = "fake-long-name-value-not-real"
vault://Billing.Svc_2-x/many-fields/field-00 = "fake-field-00-not-real"
vault://Billing.Svc_2-x/many-fields/field-01 = "fake-field-01-not-real"
vault://Billing.Svc_2-x/many-fields/field-02 = "fake-field-02-not-real"
vault://Billing.Svc_2-x/many-fields/field-03 = "fake-field-03-not-real"
vault://Billing.Svc_2-x/many-fields/field-04 = "fake-field-04-not-real"
vault://Billing.Svc_2-x/many-fields/field-05 = "fake-field-05-not-real"
vault://Billing.Svc_2-x/many-fields/field-06 = "fake-field-06-not-real"
vault://Billing.Svc_2-x/many-fields/field-07 = "fake-field-07-not-real"
vault://Billing.Svc_2-x/many-fields/field-08 = "fake-field-08-not-real"
vault://Billing.Svc_2-x/many-fields/field-09 = "fake-field-09-not-real"
vault://Billing.Svc_2-x/many-fields/field-10 = "fake-field-10-not-real"
vault://Billing.Svc_2-x/many-fields/field-11 = "fake-field-11-not-real"
vault://Billing.Svc_2-x/many-fields/field-12 = "fake-field-12-not-real"
vault://Billing.Svc_2-x/many-fields/field-13 = "fake-field-13-not-real"
vault://Billing.Svc_2-x/many-fields/field-14 = "fake-field-14-not-real"
vault://Billing.Svc_2-x/many-fields/field-15 = "fake-field-15-not-real"
vault://Billing.Svc_2-x/many-fields/field-16 = "fake-field-16-not-real"
vault://Billing.Svc_2-x/many-fields/field-17 = "fake-field-17-not-real"
vault://Billing.Svc_2-x/many-fields/field-18 = "fake-field-18-not-real"
vault://Billing.Svc_2-x/many-fields/field-19 = "fake-field-19-not-real"
vault://Billing.Svc_2-x/many-fields/field-20 = "fake-field-20-not-real"
vault://Billing.Svc_2-x/many-fields/field-21 = "fake-field-21-not-real"
vault://Billing.Svc_2-x/many-fields/field-22 = "fake-field-22-not-real"
vault://Billing.Svc_2-x/many-fields/field-23 = "fake-field-23-not-real"
vault://Billing.Svc_2-x/many-fields/field-24 = "fake-field-24-not-real"
vault://Billing.Svc_2-x/many-fields/field-25 = "fake-field-25-not-real"
vault://Billing.Svc_2-x/many-fields/field-26 = "fake-field-26-not-real"
vault://Billing.Svc_2-x/many-fields/field-27 = "fake-field-27-not-real"
vault://Billing.Svc_2-x/many-fields/field-28 = "fake-field-28-not-real"
vault://Billing.Svc_2-x/many-fields/field-29 = "fake-field-29-not-real"
vault://Billing.Svc_2-x/many-fields/field-30 = "fake-field-30-not-real"
vault://Billing.Svc_2-x/many-fields/field-31 = "fake-field-31-not-real"
vault://Billing.Svc_2-x/many-fields/field-32 = "fake-field-32-not-real"
vault://Billing.Svc_2-x/many-fields/field-33 = "fake-field-33-not-real"
vault://Billing.Svc_2-x/many-fields/field-34 = "fake-field-34-not-real"
vault://Billing.Svc_2-x/many-fields/field-35 = "fake-field-35-not-real"
vault://Billing.Svc_2-x/many-fields/field-36 = "fake-field-36-not-real"
vault://Billing.Svc_2-x/many-fields/field-37 = "fake-field-37-not-real"
vault://Billing.Svc_2-x/many-fields/field-38 = "fake-field-38-not-real"
vault://Billing.Svc_2-x/many-fields/field-39 = "fake-field-39-not-real"
```

## default-params.vault

The default Argon2id parameters (D-001) and one item. Opening it runs Argon2id at 256 MiB.

```text
fixture: default-params.vault
passphrase: "fake-passphrase-default-not-real"
kdf: m=262144 t=3 p=4
vault://demo/api/token = "fake-token-default-params-not-real"
```
