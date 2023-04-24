use crate::{account::Account, peer::Peer, Result};
use sequoia_openpgp::{KeyHandle, Cert};


/// SqlDriver is crud trait around accounts and peers.
pub trait SqlDriver {
    /// TODO: These two should return LazyCerts
    /// We should set a sort order
    fn cert(&self, account_mail: Option<&str>, kh:&KeyHandle) -> Result<Cert>;
    
    fn key(&self, account_mail: Option<&str>, kh:&KeyHandle) -> Result<Vec<Cert>>;

    fn set_cert(&self, account_mail: &str, cert: &Cert) -> Result<()>;

    fn fingerprints<'b>(&'b self, account_mail: Option<&str>) -> Box<dyn Iterator<Item=sequoia_openpgp::Fingerprint> + 'b>;
    // fn fingerprints<'b>(&'b self, account_mail: Option<&str>) -> Box<dyn Iterator<Item=openpgp::Fingerprint> + 'b> {
    /// Get an account for an email,
    /// * `canonicalized_mail` canonicalized address for easier comparisons  
    fn account(&self, account_mail: &str) -> Result<Account>;

    // fn get_account_key(&self, account_mail: Option<&str>, kh: &KeyHandle) -> Result<Cert>;

    fn set_account(&self, account: &Account) -> Result<()>;

    // fn update_account(&self, account: &Account) -> Result<()>;

    // Delete the account and all the peers account connected to an account
    // If we are using wildmode, we transfer the peers if transfer is set or
    // delete otherwise.
    // fn delete_account(&self, canonicalized_mail: &str, transfer: Option<&str>) -> Result<()>;

    /// Get a peer for an email (if it exist),
    ///
    /// * `account_mail` - An address specifying what the account the email peer
    /// should belong to. If none, we are running in wildmode and we return peer
    /// independent of account. In wildmode, there should only exist 1 peer with the
    /// same canonicalized_mail (if there is, that is an error), where in strict mode
    /// account_mail + canonicalized_mail should be unique.
    /// * `canonicalized_mail` canonicalized address for easier comparisons  
    fn peer(&self, account_mail: Option<&str>, email: &str) -> Result<Peer>;

    /// Get the cert for a keyhandler. This return the matching cert, either from the cert
    /// or the gossip.
    // fn get_peer_key(&self, account_mail: Option<&str>, kh: &KeyHandle) -> Result<Cert>;

    // should this have a wildmode?
    // fn delete_peer(&self, account_mail: Option<&str>, canonicalized_mail: &str) -> Result<()>;

    /// Inserting a peer, if we are running in wildmode we shouldn't insert
    /// a peer if it exist for another account. If get_peer is implemented correctly
    /// this shouldn't happen.
    fn set_peer(&self, peer: &Peer) -> Result<()>;

    // this is needed so we can transfer peers between accounts
    fn update_peer(&self, peer: &Peer, wildmode: bool) -> Result<()>;
}
