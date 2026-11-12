//! P3-2 (US-2 AC5, AC6): `list` and `rm`.

use vaultline::vault::Vault;

use crate::common::cli::{PASSPHRASE, Sandbox};
use crate::common::pass;

fn sandbox_with_items() -> (Sandbox, Vec<String>) {
    let sb = Sandbox::with_vault();
    let values = vec![
        sb.secret("bz", "b", "x", "z"),
        sb.secret("ak", "a", "y", "k"),
        sb.secret("ab", "a", "y", "b"),
        sb.secret("ac", "a", "x", "c"),
    ];
    (sb, values)
}

/// AC5: names, one per line, sorted, and never values.
#[test]
fn list_prints_sorted_names_and_never_values() {
    let (sb, values) = sandbox_with_items();
    let ran = sb.run_pass(&["list"], b"");
    ran.ok();
    assert_eq!(ran.stdout_str(), "a/x/c\na/y/b\na/y/k\nb/x/z\n");
    for value in &values {
        assert!(!ran.stdout_str().contains(value.as_str()));
    }
}

#[test]
fn list_with_a_project_prints_only_that_project() {
    let (sb, _) = sandbox_with_items();
    let ran = sb.run_pass(&["list", "a"], b"");
    ran.ok();
    assert_eq!(ran.stdout_str(), "a/x/c\na/y/b\na/y/k\n");
    let ran = sb.run_pass(&["list", "nothing-here"], b"");
    ran.ok();
    assert!(ran.stdout.is_empty());
}

#[test]
fn list_of_an_empty_vault_prints_nothing() {
    let sb = Sandbox::with_vault();
    let ran = sb.run_pass(&["list"], b"");
    ran.ok();
    assert!(ran.stdout.is_empty());
}

#[test]
fn list_rejects_a_bad_project_name() {
    let (sb, _) = sandbox_with_items();
    for project in ["a/b", "a b", "vault://a", ""] {
        sb.run_pass(&["list", project], b"")
            .fails_with("not a valid project name");
    }
}

/// AC6: `rm` removes the field.
#[test]
fn rm_removes_the_field_and_keeps_the_others() {
    let (sb, values) = sandbox_with_items();
    sb.run_pass(&["rm", "a/y/k"], b"").ok();
    let ran = sb.run_pass(&["list"], b"");
    assert_eq!(ran.stdout_str(), "a/x/c\na/y/b\nb/x/z\n");
    sb.run_pass(&["get", "a/y/k"], b"")
        .fails_with("vault://a/y/k");
    // The other field of the same item is still there.
    let ran = sb.run_pass(&["get", "a/y/b"], b"");
    assert_eq!(ran.stdout_str(), values[2]);
}

/// AC6: removing an item's last field removes the item.
#[test]
fn removing_the_last_field_removes_the_item() {
    let sb = Sandbox::with_vault();
    sb.secret("only", "demo", "solo", "field");
    let items = |sb: &Sandbox| {
        Vault::open(&sb.dir, &pass(PASSPHRASE))
            .unwrap()
            .items()
            .unwrap()
            .len()
    };
    assert_eq!(items(&sb), 1);
    sb.run_pass(&["rm", "demo/solo/field"], b"").ok();
    assert_eq!(items(&sb), 0);
    assert!(sb.run_pass(&["list"], b"").stdout.is_empty());
}

#[test]
fn rm_accepts_both_reference_forms() {
    let (sb, _) = sandbox_with_items();
    sb.run_pass(&["rm", "vault://a/y/k"], b"").ok();
    sb.run_pass(&["rm", "a/y/b"], b"").ok();
    assert_eq!(sb.run_pass(&["list"], b"").stdout_str(), "a/x/c\nb/x/z\n");
}

#[test]
fn rm_of_a_missing_reference_names_it_and_changes_nothing() {
    let (sb, _) = sandbox_with_items();
    let before = sb.vault_bytes();
    sb.run_pass(&["rm", "a/y/missing"], b"")
        .fails_with("vault://a/y/missing");
    sb.run_pass(&["rm", "nope/y/k"], b"")
        .fails_with("vault://nope/y/k");
    sb.run_pass(&["rm", "a/y"], b"")
        .fails_with("not a valid reference");
    assert_eq!(sb.vault_bytes(), before);
}

#[test]
fn rm_prints_nothing() {
    let (sb, _) = sandbox_with_items();
    let ran = sb.run_pass(&["rm", "a/y/k"], b"");
    ran.ok();
    assert!(ran.stdout.is_empty());
}
