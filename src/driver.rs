use sequoia_openpgp::{Fingerprint, KeyID, Cert};
use crate::{Result, peer::Peer, account::Account};

pub enum Selector<'a> {
    Email(&'a str), // canonicalized_mail email so we compare it
    Fpr(&'a Fingerprint),
    KeyID(&'a KeyID)
}

// TODO: into function from KeyHandle

/// SqlDriver is crud trait around accounts and peers.
pub trait SqlDriver {
    /// Get an account for an email, 
    /// * `canonicalized_mail` canonicalized address for easier comparisons  
    fn get_account(&self, canonicalized_mail: &str) -> Result<Account>;

    // fn insert_account(&self, canonicalized_mail: &str, cert: &Cert) -> Result<()>;

    fn update_account(&self, account: &Account) -> Result<()>;

    fn delete_account(&self, accoun: &Account) -> Result<()>;

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
    fn delete_peer(&self, peer: &Peer) -> Result<()>;

    /// Inserting a peer, if we are running in wildmode we shouldn't insert
    /// a peer if it exist for another account. If get_peer is implemented correctly
    /// this shouldn't happen.
    fn insert_peer(&self, peer: &Peer) -> Result<()>;

    /// Update a peer, 
    /// * `wildmode`, if enabled don't look at the account in peer when selecting
    /// what account to update
    fn update_peer(&self, peer: &Peer, wildmode: bool) -> Result<()>;
}
