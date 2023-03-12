use sequoia_openpgp::{Fingerprint, KeyID, KeyHandle};
use crate::{Result, peer::Peer, account::Account};

pub enum Selector<'a> {
    Email(&'a str), // canonicalized_mail email so we compare it
    Fpr(&'a Fingerprint),
    KeyID(&'a KeyID)
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
        match  value {
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

    /// Get a peer for an email (if it exist), 
    ///
    /// * `account_mail` - An address specifying what the account the email peer 
    /// should belong to. If none, we are running in wildmode and we return peer
    /// independent of account. In wildmode, there should only exist 1 peer with the
    /// same canonicalized_mail (if there is, that is an error), where in strict mode
    /// account_mail + canonicalized_mail should be unique.
    /// * `canonicalized_mail` canonicalized address for easier comparisons  
    fn get_peer(&self, account_mail: Option<&str>, selector: Selector) -> Result<Peer>;

    // should this have a wildmode?
    fn delete_peer(&self, account_mail: Option<&str>, canonicalized_mail: &str) -> Result<()>;

    /// Inserting a peer, if we are running in wildmode we shouldn't insert
    /// a peer if it exist for another account. If get_peer is implemented correctly
    /// this shouldn't happen.
    fn insert_peer(&self, peer: &Peer) -> Result<()>;

    /// Update a peer, 
    /// * `wildmode`, if enabled don't look at the account in peer when selecting
    /// what account to update
    fn update_peer(&self, peer: &Peer, wildmode: bool) -> Result<()>;
}
