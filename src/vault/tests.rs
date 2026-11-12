//! Unit tests of the vault library: `set` and `rm` semantics, P2-6
//! (`passwd`), P2-7 (`rotate`) and US-7 AC2 (the old master key can't open
//! a rotated vault).
//!
//! `passwd` and `rotate` always write the default Argon2id parameters, so the
//! two tests that prove it run Argon2id at 256 MiB. They take `HEAVY` so they
//! never run at the same time (D-040). Every other test uses cheap parameters.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use super::*;

const CHEAP: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};
static HEAVY: Mutex<()> = Mutex::new(());

fn pass(s: &str) -> Passphrase {
    Passphrase::new(s.as_bytes())
}

fn name(s: &str) -> Name {
    Name::new(s).unwrap()
}

fn value(s: &str) -> SecretValue {
    SecretValue::new(s.as_bytes())
}

struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    vault: Vault,
}

fn fixture(passphrase: &str) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vaultline");
    let vault = Vault::create(&dir, &pass(passphrase), CHEAP).unwrap();
    Fixture {
        _tmp: tmp,
        dir,
        vault,
    }
}

fn set(v: &Vault, p: &str, i: &str, f: &str, val: &str) {
    v.set(&name(p), &name(i), &name(f), &value(val)).unwrap();
}

fn get(v: &Vault, p: &str, i: &str, f: &str) -> Vec<u8> {
    v.get(&name(p), &name(i), &name(f))
        .unwrap()
        .expose()
        .to_vec()
}

fn read(dir: &Path) -> Vec<u8> {
    fs::read(dir.join(store::VAULT_FILE)).unwrap()
}

/// An item's fields as plain `(name, value)` pairs.
type Fields = Vec<(String, Vec<u8>)>;

/// Everything about a vault file, decrypted, for comparing before and after.
struct Inside {
    header: Header,
    records: Vec<Record>,
    master_key: [u8; 32],
    audit_key: [u8; 32],
    item_keys: Vec<[u8; 32]>,
    contents: Vec<(String, Fields)>,
}

fn inside(file: &[u8], passphrase: &str) -> Inside {
    let (header, master_key) = unlock(file, &pass(passphrase)).unwrap();
    let verified = verify(file, header, &master_key).unwrap();
    let decrypted = verified.decrypt_all().unwrap();
    Inside {
        header: verified.header.clone(),
        records: verified.records.clone(),
        master_key: *master_key.as_bytes(),
        audit_key: *verified.audit_key.as_bytes(),
        item_keys: decrypted.iter().map(|d| *d.item_key.as_bytes()).collect(),
        contents: decrypted
            .iter()
            .map(|d| {
                let fields = d
                    .payload
                    .fields
                    .iter()
                    .map(|(n, v)| (n.to_string(), v.expose().to_vec()))
                    .collect();
                (format!("{}/{}", d.payload.project, d.payload.item), fields)
            })
            .collect(),
    }
}

#[test]
fn create_writes_an_empty_private_vault_that_opens() {
    let f = fixture("fake-passphrase-create");
    let file = read(&f.dir);
    assert_eq!(file.len(), format::MIN_FILE_LEN);
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&f.dir), 0o700);
    assert_eq!(mode(&f.dir.join(store::VAULT_FILE)), 0o600);
    assert_eq!(mode(&f.dir.join(store::LOCK_FILE)), 0o600);
    let reopened = Vault::open(&f.dir, &pass("fake-passphrase-create")).unwrap();
    assert_eq!(reopened.vault_id(), f.vault.vault_id());
    assert_eq!(reopened.kdf_params(), CHEAP);
    assert!(reopened.kdf_params().below_defaults());
    assert!(reopened.list(None).unwrap().is_empty());
}

#[test]
fn create_refuses_an_existing_vault_and_bad_parameters() {
    let f = fixture("fake-passphrase-exists");
    let before = read(&f.dir);
    let again = Vault::create(&f.dir, &pass("fake-other-passphrase"), CHEAP);
    assert!(matches!(again, Err(Error::Exists(_))));
    assert_eq!(read(&f.dir), before);

    let tmp = tempfile::tempdir().unwrap();
    let bad = KdfParams {
        m_kib: KdfParams::MAX_M_KIB + 1,
        t: 1,
        p: 1,
    };
    let made = Vault::create(&tmp.path().join("v"), &pass("fake-passphrase"), bad);
    assert!(matches!(made, Err(Error::BadParams(_))));
    assert!(!tmp.path().join("v").exists(), "nothing is created");
}

#[test]
fn set_get_list_and_rm_follow_the_spec() {
    let f = fixture("fake-passphrase-crud");
    let v = &f.vault;
    set(v, "proj", "db", "password", "fake-db-password");
    set(v, "proj", "db", "user", "fake-db-user");
    set(v, "proj", "api", "token", "fake-api-token");
    set(v, "other", "db", "password", "fake-other-password");
    assert_eq!(get(v, "proj", "db", "password"), b"fake-db-password");

    let all: Vec<String> = v
        .list(None)
        .unwrap()
        .iter()
        .map(|e| e.to_string())
        .collect();
    assert_eq!(
        all,
        [
            "other/db/password",
            "proj/api/token",
            "proj/db/password",
            "proj/db/user"
        ]
    );
    let proj: Vec<String> = v
        .list(Some(&name("proj")))
        .unwrap()
        .iter()
        .map(|e| e.to_string())
        .collect();
    assert_eq!(proj, ["proj/api/token", "proj/db/password", "proj/db/user"]);

    set(v, "proj", "db", "password", "fake-new-password");
    assert_eq!(get(v, "proj", "db", "password"), b"fake-new-password");
    assert_eq!(v.items().unwrap().len(), 3, "updating a field adds no item");

    assert_eq!(
        v.rm(&name("proj"), &name("db"), &name("user")).unwrap(),
        Removed::Field
    );
    assert_eq!(
        v.rm(&name("proj"), &name("db"), &name("password")).unwrap(),
        Removed::Item
    );
    assert_eq!(
        v.items().unwrap().len(),
        2,
        "the item went with its last field"
    );

    let missing = v.get(&name("proj"), &name("db"), &name("password"));
    assert!(matches!(&missing, Err(Error::NotFound(r)) if r == "proj/db/password"));
    let rm_missing = v.rm(&name("proj"), &name("api"), &name("nope"));
    assert!(matches!(rm_missing, Err(Error::NotFound(_))));
    assert_eq!(
        Error::NotFound("proj/db/password".into()).to_string(),
        "no secret at vault://proj/db/password"
    );
}

#[test]
fn updating_a_field_keeps_the_item_key_and_uses_a_fresh_nonce() {
    let f = fixture("fake-passphrase-update");
    set(&f.vault, "p", "i", "a", "fake-value-one");
    set(&f.vault, "p", "j", "a", "fake-value-other");
    let before = inside(&read(&f.dir), "fake-passphrase-update");
    set(&f.vault, "p", "i", "a", "fake-value-two");
    let after = inside(&read(&f.dir), "fake-passphrase-update");

    let changed = before
        .contents
        .iter()
        .position(|(n, _)| n == "p/i")
        .unwrap();
    let untouched = 1 - changed;
    assert_eq!(
        before.records[changed].item_id,
        after.records[changed].item_id
    );
    assert_eq!(before.item_keys[changed], after.item_keys[changed]);
    assert_eq!(
        before.records[changed].ik_box,
        after.records[changed].ik_box
    );
    assert_ne!(
        before.records[changed].payload_nonce,
        after.records[changed].payload_nonce
    );
    assert_eq!(
        before.records[untouched], after.records[untouched],
        "kept byte for byte"
    );
    assert_eq!(before.header, after.header);
}

#[test]
fn values_over_64_kib_are_refused() {
    let f = fixture("fake-passphrase-limits");
    let max = SecretValue::new(&vec![b'x'; MAX_VALUE_LEN]);
    f.vault
        .set(&name("p"), &name("i"), &name("max"), &max)
        .unwrap();
    let over = SecretValue::new(&vec![b'x'; MAX_VALUE_LEN + 1]);
    let err = f.vault.set(&name("p"), &name("i"), &name("over"), &over);
    assert!(matches!(err, Err(Error::ValueTooLarge)));
    assert_eq!(get(&f.vault, "p", "i", "max").len(), MAX_VALUE_LEN);
}

#[test]
fn an_item_with_65535_fields_takes_no_new_field_but_can_be_updated() {
    let f = fixture("fake-passphrase-full-item");
    set(&f.vault, "p", "full", "f00000", "fake-first");
    // Fill the item to the limit directly, rather than with 65,535 writes.
    let current = f.vault.load().unwrap();
    let mut decrypted = current.decrypt_all().unwrap();
    let entry = decrypted.remove(0);
    let mut payload = entry.payload;
    for i in 1..usize::from(u16::MAX) {
        payload.fields.insert(name(&format!("f{i:05}")), value("v"));
    }
    let mut records = current.records.clone();
    let (nonce, sealed) = seal_payload(
        &f.vault.vault_id,
        &records[0].item_id,
        &entry.item_key,
        &payload,
    )
    .unwrap();
    records[0].payload_nonce = nonce;
    records[0].payload_box = sealed;
    let bytes = seal_file(&current.header, &records, &current.subkeys.mac).unwrap();
    fs::write(f.dir.join(store::VAULT_FILE), bytes).unwrap();

    let new_field = f.vault.set(
        &name("p"),
        &name("full"),
        &name("one-more"),
        &value("fake-x"),
    );
    assert!(matches!(new_field, Err(Error::TooManyFields)));
    set(&f.vault, "p", "full", "f00000", "fake-updated");
    assert_eq!(get(&f.vault, "p", "full", "f00000"), b"fake-updated");
    set(&f.vault, "p", "other", "field", "fake-another-item");
}

#[test]
fn a_wrong_current_passphrase_changes_nothing() {
    let f = fixture("fake-passphrase-right");
    set(&f.vault, "p", "i", "f", "fake-value");
    let before = read(&f.dir);
    let err = passwd(
        &f.dir,
        &pass("fake-passphrase-wrong"),
        &pass("fake-passphrase-new"),
    );
    assert!(matches!(err, Err(Error::Unlock)));
    assert!(matches!(
        rotate(&f.dir, &pass("fake-passphrase-wrong")),
        Err(Error::Unlock)
    ));
    assert_eq!(read(&f.dir), before);
}

#[test]
fn two_records_with_the_same_project_and_item_are_rejected() {
    let f = fixture("fake-passphrase-dup");
    set(&f.vault, "p", "i", "f", "fake-value");
    let current = f.vault.load().unwrap();
    let mut decrypted = current.decrypt_all().unwrap();
    let copy = decrypted.remove(0);
    let mut records = current.records.clone();
    let (item_id, index) = fresh_item_id(&records).unwrap();
    let (ik_nonce, ik_box) = wrap_item_key(
        &current.subkeys,
        &f.vault.vault_id,
        &item_id,
        &copy.item_key,
    )
    .unwrap();
    let (payload_nonce, payload_box) =
        seal_payload(&f.vault.vault_id, &item_id, &copy.item_key, &copy.payload).unwrap();
    records.insert(
        index,
        Record {
            item_id,
            ik_nonce,
            ik_box,
            payload_nonce,
            payload_box,
        },
    );
    let bytes = seal_file(&current.header, &records, &current.subkeys.mac).unwrap();
    fs::write(f.dir.join(store::VAULT_FILE), bytes).unwrap();

    let err = f.vault.items().err().unwrap();
    assert!(matches!(err, Error::Format(FormatError::Malformed(m)) if m.contains("same project")));
}

#[test]
fn a_vault_replaced_by_another_is_noticed() {
    let a = fixture("fake-passphrase-a");
    let b = fixture("fake-passphrase-b");
    fs::copy(b.dir.join(store::VAULT_FILE), a.dir.join(store::VAULT_FILE)).unwrap();
    let err = a.vault.items().err().unwrap();
    assert!(matches!(err, Error::Auth(m) if m.contains("different vault")));
}

/// P2-6: the old passphrase fails and the new one works; every item record
/// and the audit key's box keep their exact bytes; the salt is new and the
/// parameters are the defaults. Runs Argon2id at 256 MiB three times.
#[test]
fn passwd_rewraps_only_the_master_key() {
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let f = fixture("fake-passphrase-old");
    set(&f.vault, "p", "i", "a", "fake-value-a");
    set(&f.vault, "p", "j", "b", "fake-value-b");
    let before = inside(&read(&f.dir), "fake-passphrase-old");

    passwd(
        &f.dir,
        &pass("fake-passphrase-old"),
        &pass("fake-passphrase-new"),
    )
    .unwrap();
    let file = read(&f.dir);
    let header = format::parse_header(&file).unwrap();
    assert_eq!(header.kdf, KdfParams::DEFAULT);
    assert_ne!(header.kdf_salt, before.header.kdf_salt);
    assert_ne!(header.mk_nonce, before.header.mk_nonce);
    assert_eq!(header.vault_id, before.header.vault_id);
    assert_eq!(header.ak_nonce, before.header.ak_nonce);
    assert_eq!(header.ak_box, before.header.ak_box);
    assert_eq!(format::parse_records(&file).unwrap(), before.records);

    let old = Vault::open(&f.dir, &pass("fake-passphrase-old"));
    assert!(matches!(old, Err(Error::Unlock)));
    let after = inside(&file, "fake-passphrase-new");
    assert_eq!(
        after.master_key, before.master_key,
        "the master key is unchanged"
    );
    assert_eq!(after.contents, before.contents);
    // The handle opened before passwd keeps working: same master key.
    assert_eq!(get(&f.vault, "p", "i", "a"), b"fake-value-a");
}

/// P2-7 and US-7 AC2: the master key, every item key and every nonce change;
/// `vault_id`, every `item_id`, the audit key and the contents stay; the old
/// master key can't open the result. Runs Argon2id at 256 MiB twice.
#[test]
fn rotate_replaces_every_key_and_nonce_but_keeps_ids_and_the_audit_key() {
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let f = fixture("fake-passphrase-rotate");
    set(&f.vault, "p", "i", "a", "fake-value-a");
    set(&f.vault, "p", "i", "b", "fake-value-b");
    set(&f.vault, "q", "j", "c", "fake-value-c");
    let before_file = read(&f.dir);
    let before = inside(&before_file, "fake-passphrase-rotate");

    rotate(&f.dir, &pass("fake-passphrase-rotate")).unwrap();
    let file = read(&f.dir);
    let after = inside(&file, "fake-passphrase-rotate");

    assert_eq!(after.header.kdf, KdfParams::DEFAULT);
    assert_eq!(after.header.vault_id, before.header.vault_id);
    assert_ne!(after.header.kdf_salt, before.header.kdf_salt);
    assert_ne!(after.master_key, before.master_key);
    assert_eq!(
        after.audit_key, before.audit_key,
        "the audit key is kept (D-034)"
    );
    assert_ne!(after.header.mk_nonce, before.header.mk_nonce);
    assert_ne!(after.header.ak_nonce, before.header.ak_nonce);
    assert_ne!(after.header.ak_box, before.header.ak_box);
    assert_eq!(after.records.len(), before.records.len());
    for (i, (new, old)) in after.records.iter().zip(&before.records).enumerate() {
        assert_eq!(new.item_id, old.item_id);
        assert_ne!(new.ik_nonce, old.ik_nonce);
        assert_ne!(new.payload_nonce, old.payload_nonce);
        assert_ne!(new.ik_box, old.ik_box);
        assert_ne!(new.payload_box, old.payload_box);
        assert_ne!(after.item_keys[i], before.item_keys[i]);
    }
    assert_eq!(after.contents, before.contents);

    // US-7 AC2: the old master key fails the file MAC of the rotated vault,
    // and the handle that holds it can no longer read.
    let header = format::parse_header(&file).unwrap();
    let old_key = Key::from_slice(&before.master_key).unwrap();
    assert!(matches!(
        verify(&file, header, &old_key),
        Err(Error::Auth(_))
    ));
    assert!(matches!(f.vault.items(), Err(Error::Auth(_))));
}
