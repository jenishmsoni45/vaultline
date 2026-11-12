//! S3 (P2-3, D-003): ciphertext moved to another item's slot, or into
//! another vault, fails to open.
//!
//! The first group recomputes the file MAC with the test-only re-MAC helper
//! (`docs/design.md` §2), so each case reaches the AEAD layer and proves the
//! associated data on its own. The second group leaves the MAC alone: a
//! record spliced in from another copy or an older snapshot of the same
//! vault has the same `vault_id`, so only the file MAC catches it. Those
//! tests also show that the splice would open if the MAC were recomputed,
//! which is why the MAC is needed.

use std::fs;

use vaultline::secret::Passphrase;
use vaultline::vault::format::{self, Record};
use vaultline::vault::testing::remac;
use vaultline::vault::{Error, Vault, decrypt_bytes};

use crate::common::{TestVault, name};

/// The vault file with its records replaced, keeping the original MAC.
fn with_records(file: &[u8], records: &[Record]) -> Vec<u8> {
    let header = format::parse_header(file).unwrap();
    let mut out = format::encode_body(&header, records).unwrap();
    out.extend_from_slice(&file[file.len() - 32..]);
    out
}

/// The same, with the file MAC recomputed under the vault's own key.
fn with_records_remac(file: &[u8], records: &[Record], passphrase: &Passphrase) -> Vec<u8> {
    remac(&with_records(file, records), passphrase).unwrap()
}

fn auth_error(result: Result<Vec<vaultline::vault::Item>, Error>) -> &'static str {
    match result {
        Err(Error::Auth(what)) => what,
        Err(e) => panic!("expected an authentication error, got: {e}"),
        Ok(_) => panic!("expected an authentication error, but the vault opened"),
    }
}

fn two_item_vault() -> TestVault {
    let v = TestVault::new("fake-passphrase-s3");
    v.set("proj", "alpha", "key", b"fake-alpha-value");
    v.set("proj", "beta", "key", b"fake-beta-value");
    v
}

#[test]
fn the_unmodified_rebuild_opens() {
    // Guards the helpers: re-encoding the records unchanged, with or without
    // a recomputed MAC, gives a vault that opens.
    let v = two_item_vault();
    let file = v.bytes();
    let records = format::parse_records(&file).unwrap();
    assert_eq!(with_records(&file, &records), file);
    let rebuilt = with_records_remac(&file, &records, &v.passphrase());
    assert_eq!(decrypt_bytes(&rebuilt, &v.passphrase()).unwrap().len(), 2);
}

#[test]
fn payloads_swapped_between_items_fail() {
    let v = two_item_vault();
    let file = v.bytes();
    let mut records = format::parse_records(&file).unwrap();
    let (a, b) = records.split_at_mut(1);
    std::mem::swap(&mut a[0].payload_nonce, &mut b[0].payload_nonce);
    std::mem::swap(&mut a[0].payload_box, &mut b[0].payload_box);
    let tampered = with_records_remac(&file, &records, &v.passphrase());
    assert_eq!(
        auth_error(decrypt_bytes(&tampered, &v.passphrase())),
        "an item does not decrypt"
    );
}

#[test]
fn wrapped_keys_swapped_between_items_fail() {
    let v = two_item_vault();
    let file = v.bytes();
    let mut records = format::parse_records(&file).unwrap();
    let (a, b) = records.split_at_mut(1);
    std::mem::swap(&mut a[0].ik_nonce, &mut b[0].ik_nonce);
    std::mem::swap(&mut a[0].ik_box, &mut b[0].ik_box);
    let tampered = with_records_remac(&file, &records, &v.passphrase());
    assert_eq!(
        auth_error(decrypt_bytes(&tampered, &v.passphrase())),
        "an item key does not decrypt"
    );
}

#[test]
fn a_whole_record_moved_to_another_slot_fails() {
    // Everything of record 0 under record 1's item_id: the wrapped key and
    // the payload are both bound to item 0's ID by their associated data.
    let v = two_item_vault();
    let file = v.bytes();
    let mut records = format::parse_records(&file).unwrap();
    let moved = Record {
        item_id: records[1].item_id,
        ..records[0].clone()
    };
    records[1] = moved;
    let tampered = with_records_remac(&file, &records, &v.passphrase());
    assert_eq!(
        auth_error(decrypt_bytes(&tampered, &v.passphrase())),
        "an item key does not decrypt"
    );
}

#[test]
fn a_record_with_its_item_id_changed_fails() {
    let v = two_item_vault();
    let file = v.bytes();
    let mut records = format::parse_records(&file).unwrap();
    // Lower the first ID by one so the records stay in ascending order.
    let id = &mut records[0].item_id;
    let last = id.iter().rposition(|b| *b != 0).unwrap();
    id[last] -= 1;
    let tampered = with_records_remac(&file, &records, &v.passphrase());
    assert_eq!(
        auth_error(decrypt_bytes(&tampered, &v.passphrase())),
        "an item key does not decrypt"
    );
}

#[test]
fn a_record_moved_into_a_different_vault_fails() {
    let source = TestVault::new("fake-passphrase-s3-source");
    source.set("proj", "moved", "key", b"fake-moved-value");
    let target = two_item_vault();
    let target_file = target.bytes();
    let mut records = format::parse_records(&target_file).unwrap();
    let foreign = format::parse_records(&source.bytes()).unwrap().remove(0);
    let at = records.partition_point(|r| r.item_id < foreign.item_id);
    records.insert(at, foreign);
    let tampered = with_records_remac(&target_file, &records, &target.passphrase());
    assert_eq!(
        auth_error(decrypt_bytes(&tampered, &target.passphrase())),
        "an item key does not decrypt"
    );
}

#[test]
fn a_record_spliced_in_from_another_copy_fails_the_file_mac() {
    let original = two_item_vault();
    // A copy of the same vault (same vault_id and master key) that diverges.
    let copy_tmp = tempfile::tempdir().unwrap();
    let copy_dir = copy_tmp.path().join("vaultline");
    fs::create_dir(&copy_dir).unwrap();
    fs::set_permissions(
        &copy_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    fs::copy(original.path(), copy_dir.join("vault")).unwrap();
    let copy = Vault::open(&copy_dir, &original.passphrase()).unwrap();
    copy.set(
        &name("proj"),
        &name("gamma"),
        &name("key"),
        &vaultline::secret::SecretValue::new(b"fake-gamma-value"),
    )
    .unwrap();
    let copy_file = fs::read(copy_dir.join("vault")).unwrap();
    let file = original.bytes();
    let originals = format::parse_records(&file).unwrap();
    let spliced: Vec<Record> = format::parse_records(&copy_file)
        .unwrap()
        .into_iter()
        .filter(|r| !originals.iter().any(|o| o.item_id == r.item_id) || originals.contains(r))
        .collect();
    assert_eq!(spliced.len(), 3, "the original two records plus gamma's");

    let tampered = with_records(&file, &spliced);
    assert_eq!(
        auth_error(decrypt_bytes(&tampered, &original.passphrase())),
        "the file MAC does not match"
    );
    // Only the file MAC catches this: with it recomputed, the splice opens.
    let remacced = remac(&tampered, &original.passphrase()).unwrap();
    assert_eq!(
        decrypt_bytes(&remacced, &original.passphrase())
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn a_record_from_an_older_snapshot_fails_the_file_mac() {
    let v = two_item_vault();
    let old_file = v.bytes();
    v.set("proj", "alpha", "key", b"fake-alpha-newer-value");
    let new_file = v.bytes();
    let old_records = format::parse_records(&old_file).unwrap();
    let mut records = format::parse_records(&new_file).unwrap();
    let index = records
        .iter()
        .position(|r| {
            r.payload_box
                != old_records
                    .iter()
                    .find(|o| o.item_id == r.item_id)
                    .unwrap()
                    .payload_box
        })
        .expect("alpha's record changed");
    records[index] = old_records[index].clone();

    let tampered = with_records(&new_file, &records);
    assert_eq!(
        auth_error(decrypt_bytes(&tampered, &v.passphrase())),
        "the file MAC does not match"
    );
    // Only the file MAC catches this: recomputed, the old value comes back.
    let remacced = remac(&tampered, &v.passphrase()).unwrap();
    let items = decrypt_bytes(&remacced, &v.passphrase()).unwrap();
    let alpha = items.iter().find(|i| i.item.as_str() == "alpha").unwrap();
    assert_eq!(alpha.fields[&name("key")].expose(), b"fake-alpha-value");
}
