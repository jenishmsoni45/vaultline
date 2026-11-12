//! S1 (P2-1): opening what was sealed returns exactly the original bytes,
//! both for one payload through the AEAD and for whole vaults written to
//! disk and opened again.

use std::collections::BTreeMap;

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use vaultline::secret::SecretValue;
use vaultline::vault::crypto::{self, NONCE_LEN};
use vaultline::vault::format::{self, MAX_VALUE_LEN, Payload};
use vaultline::vault::{Vault, decrypt_bytes};

use crate::common::{TestVault, name};

fn a_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9._-]{1,64}"
}

/// Mostly short values, sometimes empty, sometimes the 64 KiB maximum.
fn a_value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        8 => vec(any::<u8>(), 0..300),
        1 => Just(Vec::new()),
        1 => vec(any::<u8>(), MAX_VALUE_LEN..=MAX_VALUE_LEN),
    ]
}

fn fields() -> impl Strategy<Value = BTreeMap<String, Vec<u8>>> {
    btree_map(a_name(), a_value(), 1..8)
}

type Contents = BTreeMap<(String, String), BTreeMap<String, Vec<u8>>>;

fn contents() -> impl Strategy<Value = Contents> {
    btree_map((a_name(), a_name()), fields(), 0..6)
}

fn as_contents(items: Vec<vaultline::vault::Item>) -> Contents {
    items
        .into_iter()
        .map(|item| {
            let fields = item
                .fields
                .iter()
                .map(|(n, v)| (n.to_string(), v.expose().to_vec()))
                .collect();
            ((item.project.to_string(), item.item.to_string()), fields)
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn a_payload_survives_encode_seal_open_decode(
        project in a_name(),
        item in a_name(),
        fields in fields(),
        aad in vec(any::<u8>(), 0..64),
    ) {
        let payload = Payload {
            project: name(&project),
            item: name(&item),
            fields: fields.iter().map(|(n, v)| (name(n), SecretValue::new(v))).collect(),
        };
        let plain = format::encode_payload(&payload).unwrap();
        let key = crypto::random_key().unwrap();
        let nonce: [u8; NONCE_LEN] = crypto::random_array().unwrap();
        let sealed = crypto::seal(&key, &nonce, &aad, plain.expose()).unwrap();
        let opened = crypto::open(&key, &nonce, &aad, &sealed).unwrap();
        prop_assert_eq!(opened.expose(), plain.expose());
        let back = format::decode_payload(opened.expose()).unwrap();
        prop_assert_eq!(back.project.as_str(), project.as_str());
        prop_assert_eq!(back.item.as_str(), item.as_str());
        let back_fields: BTreeMap<String, Vec<u8>> = back
            .fields
            .iter()
            .map(|(n, v)| (n.to_string(), v.expose().to_vec()))
            .collect();
        prop_assert_eq!(back_fields, fields);
    }
}

proptest! {
    // Each case creates a vault and writes it once per field, with a flush to
    // disk each time, so fewer cases.
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn a_whole_vault_survives_write_and_open(expected in contents()) {
        let v = TestVault::new("fake-passphrase-s1-roundtrip");
        for ((project, item), fields) in &expected {
            for (field, val) in fields {
                v.set(project, item, field, val);
            }
        }
        let reopened = Vault::open(&v.dir, &v.passphrase()).unwrap();
        prop_assert_eq!(&as_contents(reopened.items().unwrap()), &expected);
        let from_bytes = decrypt_bytes(&v.bytes(), &v.passphrase()).unwrap();
        prop_assert_eq!(&as_contents(from_bytes), &expected);
        for ((project, item), fields) in &expected {
            for (field, val) in fields {
                let got = reopened.get(&name(project), &name(item), &name(field)).unwrap();
                prop_assert_eq!(got.expose(), val.as_slice());
            }
        }
    }
}
