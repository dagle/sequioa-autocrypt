use crate::{account::Account, peer::Peer, Result};
use sequoia_openpgp::{Fingerprint, KeyHandle, KeyID};

pub enum Selector<'a> {
    Email(&'a str), // canonicalized_mail email so we compare it
    Fpr(&'a Fingerprint),
    KeyID(&'a KeyID),
}

impl<'a> From<&'a Fingerprint> for Selector<'a> {
    fn from(value: &'a Fingerprint) -> Self {
        Self::Fpr(value)
    }
}

impl<'a> From<&'a KeyID> for Selector<'a> {
    fn from(value: &'a KeyID) -> Self {
        Self::KeyID(value)
    }
}

impl<'a> From<&'a str> for Selector<'a> {
    fn from(value: &'a str) -> Self {
        Self::Email(value)
    }
}

impl<'a> From<&'a KeyHandle> for Selector<'a> {
    fn from(value: &'a KeyHandle) -> Self {
        match value {
            KeyHandle::Fingerprint(fpr) => Self::Fpr(fpr),
            KeyHandle::KeyID(id) => Self::KeyID(id),
        }
    }
}

/// SqlDriver is crud trait around accounts and peers.
pub trait SqlDriver {
    /// Get an account for an email,
    /// * `canonicalized_mail` canonicalized address for easier comparisons  
    fn get_account(&self, canonicalized_mail: &str) -> Result<Account>;

    fn insert_account(&self, account: &Account) -> Result<()>;

    fn update_account(&self, account: &Account) -> Result<()>;

    // Delete the account and all the peers account connected to an account
    // If we are using wildmode, we transfer the peers if transfer is set or
    // delete otherwise.
    fn delete_account(&self, canonicalized_mail: &str, transfer: Option<&str>) -> Result<()>;

    /// Inserting a peer, if we are running in wildmode we shouldn't insert
    /// a peer if it exist for another account. If get_peer is implemented correctly
    /// this shouldn't happen.
    fn insert_peer(&self, peer: &Peer) -> Result<()>;

    /// Get a peer for an email (if it exist),
    ///
    /// * `account_mail` - An address specifying what the account the email peer should belong to.
    /// * `selector`- What we select on to find our peer
    fn get_peer(&self, account_mail: &str, selector: Selector) -> Result<Peer>;

    fn delete_peer(&self, peer: Peer) -> Result<()>;

    fn update_peer(&self, peer: &Peer) -> Result<()>;
}

pub trait WildDriver {
    /// Get a peer for an email (if it exist),
    /// This function works like get_peer but doesn't care about the account_mail.
    /// This makes it possible to share peers between accounts
    ///
    /// * `selector`- What we select on to find our peer
    fn get_wild_peer(&self, selector: Selector) -> Result<Peer>;
}
