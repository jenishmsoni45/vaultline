//! S5 (P2-5): every v1 fixture opens with exactly the contents its README
//! lists, and the README lists only fake values.
//!
//! Opening `default-params.vault` runs Argon2id at 256 MiB, once (D-020).

use std::collections::BTreeMap;
use std::fs;

use vaultline::vault::Vault;

use crate::common::fixture_readme::{self, fixtures_dir};
use crate::common::{fixture_bytes, install, pass};

#[test]
fn every_fixture_opens_with_its_readme_contents() {
    for spec in fixture_readme::load() {
        let (_tmp, dir) = install(&fixture_bytes(&spec.file));
        let vault = Vault::open(&dir, &pass(&spec.passphrase))
            .unwrap_or_else(|e| panic!("{} doesn't open: {e}", spec.file));
        assert_eq!(
            vault.kdf_params(),
            spec.kdf,
            "{}: Argon2id parameters",
            spec.file
        );

        let expected: BTreeMap<String, Vec<u8>> = spec
            .fields
            .iter()
            .map(|f| (f.reference(), f.value.bytes()))
            .collect();
        assert_eq!(
            expected.len(),
            spec.fields.len(),
            "{}: duplicate lines",
            spec.file
        );
        let actual: BTreeMap<String, Vec<u8>> = vault
            .items()
            .unwrap()
            .iter()
            .flat_map(|item| {
                item.fields.iter().map(move |(field, value)| {
                    (
                        format!("{}/{}/{field}", item.project, item.item),
                        value.expose().to_vec(),
                    )
                })
            })
            .collect();
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{}: field names",
            spec.file
        );
        for (reference, value) in &expected {
            assert!(
                actual[reference] == *value,
                "{}: wrong value for {reference}",
                spec.file
            );
        }
    }
}

#[test]
fn the_readme_covers_exactly_the_fixture_files() {
    let mut listed: Vec<String> = fixture_readme::load().into_iter().map(|s| s.file).collect();
    listed.sort();
    let mut present: Vec<String> = fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".vault"))
        .collect();
    present.sort();
    assert_eq!(listed, present);
    assert_eq!(
        listed,
        ["basic.vault", "default-params.vault", "empty.vault"]
    );
}

#[test]
fn the_readme_lists_only_fake_values() {
    for spec in fixture_readme::load() {
        assert!(
            spec.passphrase.contains("fake"),
            "{}: passphrase",
            spec.file
        );
        for field in &spec.fields {
            assert!(
                field.value.is_obviously_fake(),
                "{}: {} doesn't look fake",
                spec.file,
                field.reference()
            );
        }
    }
}

#[test]
fn basic_vault_has_the_edge_cases_the_format_doc_asks_for() {
    // docs/vault-format.md §7: an empty value, a 64 KiB value, names using
    // every allowed character class, and an item with many fields.
    let spec = fixture_readme::load()
        .into_iter()
        .find(|s| s.file == "basic.vault")
        .unwrap();
    let projects: std::collections::BTreeSet<&str> =
        spec.fields.iter().map(|f| f.project.as_str()).collect();
    assert_eq!(projects.len(), 2, "two projects");
    assert!(spec.fields.iter().any(|f| f.value.bytes().is_empty()));
    assert!(spec.fields.iter().any(|f| f.value.bytes().len() == 65_536));
    let names: String = spec
        .fields
        .iter()
        .flat_map(|f| [f.project.clone(), f.item.clone(), f.field.clone()])
        .collect();
    for class in [
        |c: char| c.is_ascii_uppercase(),
        |c: char| c.is_ascii_lowercase(),
        |c: char| c.is_ascii_digit(),
        |c: char| c == '.',
        |c: char| c == '_',
        |c: char| c == '-',
    ] {
        assert!(names.chars().any(class), "a character class is missing");
    }
    assert!(
        spec.fields.iter().any(|f| f.item.len() == 64),
        "a 64-byte name"
    );
    assert!(
        spec.fields.iter().any(|f| f.field.len() == 1),
        "a 1-byte name"
    );
    let mut per_item: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for f in &spec.fields {
        *per_item.entry((&f.project, &f.item)).or_default() += 1;
    }
    assert!(
        per_item.values().any(|&n| n >= 40),
        "an item with many fields"
    );
}
