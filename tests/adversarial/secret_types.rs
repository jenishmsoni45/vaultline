//! P2-12, NFR-3 (D-039): no type that holds a secret implements `Debug` or
//! `Display`, so no secret can be formatted into a message by accident.

use std::fmt::{Debug, Display};

use static_assertions::assert_not_impl_any;
use vaultline::secret::{Key, Passphrase, SecretBytes, SecretValue};
use vaultline::vault::crypto::Subkeys;
use vaultline::vault::format::Payload;
use vaultline::vault::{Item, Vault};

assert_not_impl_any!(Key: Debug, Display);
assert_not_impl_any!(Passphrase: Debug, Display);
assert_not_impl_any!(SecretValue: Debug, Display);
assert_not_impl_any!(SecretBytes: Debug, Display);
assert_not_impl_any!(Subkeys: Debug, Display);
assert_not_impl_any!(Payload: Debug, Display);
assert_not_impl_any!(Item: Debug, Display);
assert_not_impl_any!(Vault: Debug, Display);

// None of them can be copied around implicitly either.
assert_not_impl_any!(Key: Clone, Copy);
assert_not_impl_any!(Passphrase: Clone, Copy);
assert_not_impl_any!(SecretValue: Clone, Copy);
assert_not_impl_any!(SecretBytes: Clone, Copy);

#[test]
fn secret_types_have_no_debug_or_display() {
    // The assertions above are checked when this file compiles; this test
    // makes the check show up in the test list.
}
