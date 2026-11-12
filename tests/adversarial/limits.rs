//! P2-9, NFR-11: size limits. A file over 64 MiB is rejected before it is
//! read, a value over 64 KiB is rejected, and an `item_count` larger than the
//! file can hold is rejected before anything is allocated. Names are 1–64
//! bytes.

use std::fs::OpenOptions;

use vaultline::vault::format::{self, FormatError, MAX_FILE_LEN, MAX_VALUE_LEN};
use vaultline::vault::testing::{kdf_calls, remac};
use vaultline::vault::{Error, Name, NameError, Vault};

use crate::common::{TestVault, install, name, value};

#[test]
fn a_file_over_64_mib_is_rejected_before_it_is_read() {
    let v = TestVault::new("fake-passphrase-big-file");
    // A sparse file: 64 MiB + 1 byte long, taking no space on disk.
    let file = OpenOptions::new().write(true).open(v.path()).unwrap();
    file.set_len(MAX_FILE_LEN + 1).unwrap();
    drop(file);
    let before = kdf_calls();
    let err = Vault::open(&v.dir, &v.passphrase())
        .err()
        .expect("open must fail");
    assert_eq!(kdf_calls(), before);
    assert!(
        matches!(err, Error::Format(FormatError::Malformed(m)) if m.contains("larger than 64 MiB")),
        "{err}"
    );
    assert!(format::check_file_len(MAX_FILE_LEN).is_ok());
}

#[test]
fn a_file_shorter_than_an_empty_vault_is_rejected() {
    let v = TestVault::new("fake-passphrase-short-file");
    for len in [0, 1, 54, 202, 233] {
        let (_tmp, dir) = install(&v.bytes()[..len]);
        let err = Vault::open(&dir, &v.passphrase())
            .err()
            .expect("open must fail");
        assert!(matches!(err, Error::Format(_)), "{len}: {err}");
    }
}

#[test]
fn values_are_limited_to_64_kib() {
    let v = TestVault::new("fake-passphrase-big-value");
    let max = vec![b'v'; MAX_VALUE_LEN];
    v.vault
        .set(&name("p"), &name("i"), &name("max"), &value(&max))
        .unwrap();
    let got = v.vault.get(&name("p"), &name("i"), &name("max")).unwrap();
    assert_eq!(got.len(), MAX_VALUE_LEN);

    let before = v.bytes();
    let over = vec![b'v'; MAX_VALUE_LEN + 1];
    let err = v
        .vault
        .set(&name("p"), &name("i"), &name("over"), &value(&over));
    assert!(matches!(err, Err(Error::ValueTooLarge)));
    assert_eq!(v.bytes(), before, "nothing was written");
}

#[test]
fn an_item_count_beyond_the_file_is_rejected_before_allocation() {
    let v = TestVault::new("fake-passphrase-item-count");
    v.set("proj", "item", "field", b"fake-item-count-value");
    for count in [2u32, 1_000, u32::MAX] {
        let mut bytes = v.bytes();
        bytes[198..202].copy_from_slice(&count.to_le_bytes());
        assert_eq!(
            format::parse_records(&bytes),
            Err(FormatError::Malformed(
                "item_count is larger than the file can hold"
            ))
        );
        // Through the whole open path, with the file MAC recomputed so the
        // record parser is reached.
        let (_tmp, dir) = install(&remac(&bytes, &v.passphrase()).unwrap());
        let err = Vault::open(&dir, &v.passphrase())
            .err()
            .expect("open must fail");
        assert!(
            matches!(err, Error::Format(FormatError::Malformed(m)) if m.contains("item_count")),
            "{err}"
        );
    }
}

#[test]
fn names_are_one_to_64_allowed_bytes() {
    assert!(Name::new(&"n".repeat(64)).is_ok());
    assert_eq!(Name::new(&"n".repeat(65)), Err(NameError::TooLong));
    assert_eq!(Name::new(""), Err(NameError::Empty));
    assert_eq!(Name::new("has space"), Err(NameError::BadByte));
}

// ---- Phase 3: templates and env files (NFR-11, P3-3, P3-4) ----

const SIXTEEN_MIB: u64 = 16 * 1024 * 1024;

/// A template over 16 MiB is rejected, and exactly 16 MiB is not. The file is
/// sparse, so it takes no space on disk.
#[test]
fn a_template_is_limited_to_16_mib() {
    use crate::common::cli::Sandbox;
    let sb = Sandbox::new();
    let path = sb.work.join("big.tpl");

    let file = std::fs::File::create(&path).unwrap();
    file.set_len(SIXTEEN_MIB + 1).unwrap();
    let ran = sb.run(&["inject", "-i", path.to_str().unwrap()], b"");
    ran.fails_with("larger than the 16 MiB limit");
    assert!(ran.stdout.is_empty());

    file.set_len(SIXTEEN_MIB).unwrap();
    let ran = sb.run(&["inject", "-i", path.to_str().unwrap()], b"");
    ran.ok();
    assert_eq!(ran.stdout.len() as u64, SIXTEEN_MIB);
}

/// The same limit applies to a template on standard input, which is read only
/// up to the limit.
#[test]
fn a_template_on_stdin_is_limited_to_16_mib() {
    use crate::common::cli::Sandbox;
    let sb = Sandbox::new();
    // The first line is the passphrase (D-037); the template is what follows.
    let mut stdin = b"unused-passphrase\n".to_vec();
    stdin.extend(vec![b'x'; SIXTEEN_MIB as usize + 1]);
    let ran = sb.run(&["inject"], &stdin);
    ran.fails_with("larger than the 16 MiB limit");
    assert!(ran.stdout.is_empty());
}

/// An env file over 16 MiB is rejected, and exactly 16 MiB is not.
#[test]
fn an_env_file_is_limited_to_16_mib() {
    use crate::common::cli::Sandbox;
    let sb = Sandbox::new();
    let path = sb.work.join("big.env");
    let started = sb.work.join("started");
    let script = "touch started";

    // All comment, so that it is valid at exactly the limit.
    std::fs::write(&path, vec![b'#'; SIXTEEN_MIB as usize]).unwrap();
    sb.run(
        &["run", "--env-file", "big.env", "--", "sh", "-c", script],
        b"",
    )
    .ok();
    assert!(started.exists());
    std::fs::remove_file(&started).unwrap();

    std::fs::write(&path, vec![b'#'; SIXTEEN_MIB as usize + 1]).unwrap();
    sb.run(
        &["run", "--env-file", "big.env", "--", "sh", "-c", script],
        b"",
    )
    .fails_with("larger than the 16 MiB limit");
    assert!(!started.exists(), "the child must not start");
}

/// Hostile templates finish quickly: scanning is linear.
#[test]
fn hostile_templates_are_handled_in_linear_time() {
    use crate::common::cli::Sandbox;
    let sb = Sandbox::new();
    for pattern in ["{{ ", "{{", "{", "{{\t{{\t"] {
        let template = pattern.repeat(2_000_000 / pattern.len());
        let started = std::time::Instant::now();
        let mut stdin = b"unused-passphrase\n".to_vec();
        stdin.extend_from_slice(template.as_bytes());
        let ran = sb.run(&["inject"], &stdin);
        ran.ok();
        assert_eq!(ran.stdout, template.as_bytes(), "{pattern:?}");
        assert!(started.elapsed().as_secs() < 30, "{pattern:?} was slow");
    }
}
