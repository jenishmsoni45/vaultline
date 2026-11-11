//! P2-13, US-9 AC4, threat model C1: no name and no value appears in the
//! vault bytes.
//!
//! Strings shorter than 8 bytes, such as a 1-byte name or the empty value,
//! turn up in random ciphertext by chance, so only names and values of 8
//! bytes or more are checked (D-042). The generated vaults use distinctive
//! `fake-` markers of that length.

use proptest::collection::btree_map;
use proptest::prelude::*;

use crate::common::fixture_readme;
use crate::common::{TestVault, contains, fixture_bytes};

const MIN_CHECKED_LEN: usize = 8;

fn assert_absent(file: &[u8], needles: &[Vec<u8>], what: &str) {
    for needle in needles.iter().filter(|n| n.len() >= MIN_CHECKED_LEN) {
        assert!(
            !contains(file, needle),
            "{what}: {:?} appears in the vault bytes",
            String::from_utf8_lossy(&needle[..needle.len().min(40)])
        );
    }
}

#[test]
fn no_fixture_contains_its_names_values_or_passphrase() {
    for spec in fixture_readme::load() {
        let file = fixture_bytes(&spec.file);
        let mut needles = vec![spec.passphrase.clone().into_bytes()];
        for field in &spec.fields {
            needles.push(field.project.clone().into_bytes());
            needles.push(field.item.clone().into_bytes());
            needles.push(field.field.clone().into_bytes());
            needles.push(field.value.bytes());
            needles.push(field.reference().into_bytes());
        }
        let checked = needles
            .iter()
            .filter(|n| n.len() >= MIN_CHECKED_LEN)
            .count();
        assert!(
            checked > 0 || spec.fields.is_empty(),
            "{}: nothing checked",
            spec.file
        );
        assert_absent(&file, &needles, &spec.file);
    }
}

fn a_marker() -> impl Strategy<Value = String> {
    "fake-[a-z0-9]{3,40}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn generated_vaults_contain_no_names_or_values(
        contents in btree_map((a_marker(), a_marker()), btree_map(a_marker(), a_marker(), 1..4), 1..5),
    ) {
        let passphrase = "fake-passphrase-no-plaintext";
        let v = TestVault::new(passphrase);
        let mut needles = vec![passphrase.as_bytes().to_vec()];
        for ((project, item), fields) in &contents {
            for (field, val) in fields {
                v.set(project, item, field, val.as_bytes());
                needles.extend([project, item, field, val].map(|s| s.as_bytes().to_vec()));
            }
        }
        assert_absent(&v.bytes(), &needles, "generated vault");
        // Names stay hidden after a removal re-encrypts an item, too.
        let ((project, item), fields) = contents.iter().next().unwrap();
        let field = fields.keys().next().unwrap();
        v.vault
            .rm(&crate::common::name(project), &crate::common::name(item), &crate::common::name(field))
            .unwrap();
        assert_absent(&v.bytes(), &needles, "generated vault after rm");
    }
}
