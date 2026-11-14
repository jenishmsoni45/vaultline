//! What both paths do with an unlocked vault (`docs/architecture.md` §2,
//! `docs/design.md` §4 and §9, D-014, D-030, D-047, D-048).
//!
//! A command that works in its own process and the agent answer the same
//! requests, and each one leaves the same audit records. Keeping that here, in
//! one place, means the two paths can't drift apart.
//!
//! The order is always: check the audit log (D-047), then read or change the
//! vault, then append the records. A damaged log therefore stops a read before
//! a secret is decrypted and a write before the vault changes. A write that
//! succeeds but can't be recorded is reported as such
//! ([`AuditError::Recording`]).

use std::collections::BTreeSet;
use std::path::Path;

use crate::audit::{
    self, Anchor, Audit, AuditError, Entry, Event, LOCK_BY_COMMAND, LOCK_BY_STOP, UNLOCK_BY_AGENT,
    UNLOCK_BY_COMMAND, Verdict,
};
use crate::inject::reference::Reference;
use crate::inject::template::Resolved;
use crate::secret::{Key, Passphrase, SecretValue};
use crate::vault::crypto::ID_LEN;
use crate::vault::{Error, Name, Removed, Vault};

/// Who unlocked the vault, which `unlock` records carry as their detail
/// (`vault-format.md` §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A command unlocked it for itself.
    Command,
    /// The agent unlocked it.
    Agent,
}

/// Why a set of references couldn't be resolved.
#[derive(Debug)]
pub enum ResolveError {
    /// This reference names nothing in the vault (D-028).
    Missing(Reference),
    /// The vault or the audit log refused.
    Failed(Error),
}

impl From<Error> for ResolveError {
    fn from(e: Error) -> Self {
        ResolveError::Failed(e)
    }
}

impl From<AuditError> for ResolveError {
    fn from(e: AuditError) -> Self {
        ResolveError::Failed(e.into())
    }
}

/// Opens the vault with `passphrase`, and keeps the books (§5.5, D-016):
///
/// - a wrong passphrase raises the failed-unlock counter;
/// - a right one appends `unlock`, then `failed-unlocks` if the counter isn't
///   0, and resets the counter.
///
/// If the audit log can't be appended to, the unlock fails and the vault is
/// closed again (D-047).
pub fn open(dir: &Path, passphrase: &Passphrase, origin: Origin) -> Result<Vault, Error> {
    let vault = match Vault::open(dir, passphrase) {
        Ok(vault) => vault,
        Err(Error::Unlock) => {
            // Nothing more can be done if the counter can't be written.
            let _ = audit::note_failed_unlock(dir);
            return Err(Error::Unlock);
        }
        Err(e) => return Err(e),
    };
    Session::new(&vault).record_unlock(origin)?;
    Ok(vault)
}

/// An unlocked vault and the audit log that goes with it.
pub struct Session<'v> {
    vault: &'v Vault,
}

impl<'v> Session<'v> {
    pub fn new(vault: &'v Vault) -> Session<'v> {
        Session { vault }
    }

    pub fn vault(&self) -> &Vault {
        self.vault
    }

    /// Runs `f` with the audit log, after the checks of D-047.
    fn checked<T>(&self, f: impl FnOnce(&Audit<'_>) -> Result<T, Error>) -> Result<T, Error> {
        let key = self.vault.audit_key()?;
        let audit = Audit::new(self.vault.dir(), self.vault.vault_id(), &key);
        audit.check()?;
        f(&audit)
    }

    /// Appends records for a change that has already been made.
    fn recording(audit: &Audit<'_>, entries: &[Entry]) -> Result<(), Error> {
        audit
            .append_locked(entries)
            .map_err(|e| Error::Audit(AuditError::Recording(Box::new(e))))
    }

    /// Appends `unlock`, and `failed-unlocks` when there is a tally (§5.5).
    fn record_unlock(&self, origin: Origin) -> Result<(), Error> {
        let dir = self.vault.dir();
        let key = self.vault.audit_key()?;
        let audit = Audit::new(dir, self.vault.vault_id(), &key);
        let lock = audit::lock(dir)?;
        let failures = audit::read_counter(dir);
        let detail = match origin {
            Origin::Command => UNLOCK_BY_COMMAND,
            Origin::Agent => UNLOCK_BY_AGENT,
        };
        let mut entries = vec![Entry::new(Event::Unlock, detail)];
        if failures != 0 {
            entries.push(Entry::new(Event::FailedUnlocks, failures));
        }
        audit.append(&lock, &entries)?;
        if failures != 0 {
            audit::reset_counter(dir, &lock)?;
        }
        Ok(())
    }

    /// Looks every reference up, all or nothing (§4.1), and appends one `read`
    /// per distinct item that was read (§9). Nothing is returned, and nothing
    /// is recorded, if any reference is missing.
    pub fn resolve(&self, references: &BTreeSet<&Reference>) -> Result<Resolved, ResolveError> {
        let mut resolved = Resolved::new();
        if references.is_empty() {
            return Ok(resolved);
        }
        self.checked(|audit| {
            let items = self.vault.items()?;
            let mut read: Vec<[u8; ID_LEN]> = Vec::new();
            for reference in references {
                let found = items
                    .iter()
                    .find(|i| i.project == reference.project && i.item == reference.item)
                    .and_then(|i| i.fields.get(&reference.field).map(|v| (i.item_id, v)));
                let Some((item_id, value)) = found else {
                    return Ok(Err(ResolveError::Missing((*reference).clone())));
                };
                if !read.contains(&item_id) {
                    read.push(item_id);
                }
                resolved.insert((*reference).clone(), value.duplicate());
            }
            let entries: Vec<Entry> = read
                .into_iter()
                .map(|id| Entry::for_item(Event::Read, id, 0))
                .collect();
            audit.append_locked(&entries)?;
            Ok(Ok(()))
        })?
        .map(|()| resolved)
    }

    /// `set` (§4), and its `set` record.
    pub fn set(&self, reference: &Reference, value: &SecretValue) -> Result<(), Error> {
        self.checked(|audit| {
            let id =
                self.vault
                    .put(&reference.project, &reference.item, &reference.field, value)?;
            Self::recording(audit, &[Entry::for_item(Event::Set, id, 0)])
        })
    }

    /// `rm` (§4), and its `rm` record: detail 0 for a field, 1 for a whole item.
    pub fn rm(&self, reference: &Reference) -> Result<Removed, Error> {
        self.checked(|audit| {
            let (removed, id) =
                self.vault
                    .remove(&reference.project, &reference.item, &reference.field)?;
            let detail = u64::from(removed == Removed::Item);
            Self::recording(audit, &[Entry::for_item(Event::Rm, id, detail)])?;
            Ok(removed)
        })
    }

    /// `list`: names only, so nothing is read and nothing is recorded (D-037).
    pub fn list(&self, project: Option<&Name>) -> Result<Vec<crate::vault::Entry>, Error> {
        self.vault.list(project)
    }

    /// `passwd`, and its `passwd` record.
    pub fn passwd(&self, new: &Passphrase) -> Result<(), Error> {
        self.checked(|audit| {
            self.vault.passwd(new)?;
            Self::recording(audit, &[Entry::new(Event::Passwd, 0)])
        })
    }

    /// `rotate`, and its `rotate` record. The audit key doesn't change, so the
    /// record is written with the key fetched before the rotation. The `Vault`
    /// holds the old master key afterwards and should be dropped.
    pub fn rotate(&self, passphrase: &Passphrase) -> Result<(), Error> {
        self.checked(|audit| {
            self.vault.rotate(passphrase)?;
            Self::recording(audit, &[Entry::new(Event::Rotate, 0)])
        })
    }

    /// `audit verify`: checks everything in §5.6 and appends the result.
    pub fn audit_verify(&self, expect: Option<Anchor>) -> Result<Verdict, Error> {
        let key: Key = self.vault.audit_key()?;
        let audit = Audit::new(self.vault.dir(), self.vault.vault_id(), &key);
        Ok(audit.verify_and_record(expect)?)
    }

    /// `audit head`: the current anchor, after checking the head's MAC.
    pub fn audit_head(&self) -> Result<Anchor, Error> {
        let key = self.vault.audit_key()?;
        let audit = Audit::new(self.vault.dir(), self.vault.vault_id(), &key);
        Ok(audit.anchor()?)
    }

    /// Appends a `lock` or `idle-timeout` record for the agent as it wipes its
    /// key. Best effort by design (D-048): if the vault no longer verifies
    /// under this key, for example after `rotate`, there is no audit key to be
    /// had, and the record is skipped. [`Recorded::Skipped`] says so.
    pub fn record_lock(&self, event: LockEvent) -> Result<Recorded, Error> {
        let (event, detail) = match event {
            LockEvent::Locked => (Event::Lock, LOCK_BY_COMMAND),
            LockEvent::Stopped => (Event::Lock, LOCK_BY_STOP),
            LockEvent::IdleTimeout => (Event::IdleTimeout, 0),
        };
        let key = match self.vault.audit_key() {
            Ok(key) => key,
            Err(Error::Auth(_) | Error::Format(_) | Error::Unlock) => return Ok(Recorded::Skipped),
            Err(e) => return Err(e),
        };
        let audit = Audit::new(self.vault.dir(), self.vault.vault_id(), &key);
        audit.append_locked(&[Entry::new(event, detail)])?;
        Ok(Recorded::Written)
    }
}

/// Why the agent is wiping its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    /// `vaultline lock`.
    Locked,
    /// `agent stop`, or a signal.
    Stopped,
    /// The idle timer ran out.
    IdleTimeout,
}

/// Whether [`Session::record_lock`] wrote a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    Written,
    /// The vault no longer verifies under the agent's key (D-048).
    Skipped,
}
