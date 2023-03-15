extern crate sequoia_openpgp as openpgp;
use std::{
    borrow::Cow,
    cmp::Ordering,
    io::{self, Read, Write},
    time::SystemTime,
};

use crate::{
    account::Account,
    driver::{Selector, SqlDriver},
    peer::{Peer, Prefer},
    sq::{remove_password, set_password, SessionKey},
    Result,
};
use crate::{
    sq::{DHelper, VHelper},
    uirecommendation::UIRecommendation,
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use openpgp::packet::prelude::SecretKeyMaterial::{Encrypted, Unencrypted};
use openpgp::{
    cert::{amalgamation::ValidateAmalgamation, CertBuilder, CipherSuite},
    crypto::{self, Password},
    packet::Signature,
    parse::{
        stream::{DecryptorBuilder, DetachedVerifierBuilder, VerifierBuilder},
        Parse,
    },
    policy::Policy,
    serialize::stream::{self, Armorer, Compressor, Encryptor, LiteralWriter, Recipient, Signer},
    types::{CompressionAlgorithm, KeyFlags},
    Cert,
};
use sequoia_autocrypt::{
    AutocryptHeader, AutocryptHeaderType, AutocryptSetupMessage, AutocryptSetupMessageParser,
};

pub struct AutocryptStore<T: SqlDriver> {
    pub(crate) password: Option<Password>,
    wildmode: bool,
    pub(crate) conn: T,
}

macro_rules! check_mode {
    ($self:ident, $account_mail:expr) => {
        if !$self.wildmode && $account_mail.is_none() {
            return Err(anyhow::anyhow!(
                "You need to specify an account when the database isn't running in wildcard mode"
            ));
        }
    };
}

impl<T: SqlDriver> AutocryptStore<T> {
    pub fn new(conn: T, password: Option<&str>, wildmode: bool) -> Result<Self> {
        Ok(AutocryptStore {
            password: password.map(Password::from),
            conn,
            wildmode,
        })
    }

    fn account(&self, canonicalized_mail: &str) -> Result<Account> {
        self.conn.get_account(canonicalized_mail)
    }

    pub fn set_prefer(&self, canonicalized_mail: &str, prefer: Prefer) -> Result<()> {
        let mut account = self.conn.get_account(canonicalized_mail)?;
        account.prefer = prefer;
        self.conn.insert_account(&account)
    }

    pub fn prefer(&self, canonicalized_mail: &str) -> Result<Prefer> {
        let account = self.conn.get_account(canonicalized_mail)?;
        Ok(account.prefer)
    }

    pub fn set_enable(&self, canonicalized_mail: &str, enable: bool) -> Result<()> {
        let mut account = self.conn.get_account(canonicalized_mail)?;
        account.enable = enable;
        self.conn.insert_account(&account)
    }

    pub fn enable(&self, canonicalized_mail: &str) -> Result<bool> {
        let account = self.conn.get_account(canonicalized_mail)?;
        Ok(account.enable)
    }

    fn peer<'a, S>(&self, account_mail: Option<&str>, selector: S) -> Result<Peer>
    where
        S: Into<Selector<'a>>,
    {
        check_mode!(self, account_mail);

        self.conn.get_peer(account_mail, selector.into())
    }

    fn gen_cert(&self, account_mail: &str, now: SystemTime) -> Result<(Cert, Signature)> {
        let mut builder = CertBuilder::new();
        builder = builder.add_userid(account_mail);
        builder = builder.set_creation_time(now);

        builder = builder.set_validity_period(None);

        // builder = builder.set_validity_period(
        //     Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),

        builder = builder.set_cipher_suite(CipherSuite::Cv25519);

        builder = builder.add_signing_subkey();
        // We set storage_encryption so we can store drafts
        builder = builder.add_subkey(KeyFlags::empty().set_transport_encryption().set_storage_encryption(), None, None);

        builder = builder.set_password(self.password.clone());

        builder.generate()
    }

    /// Update the private key the account for our mail. If the current key is
    /// is still usable, no update is done.
    pub fn update_private_key(&self, policy: &dyn Policy, account_mail: &str) -> Result<()> {
        let now = SystemTime::now();

        // Check if we have a key, if that is the case, check if the key is ok.
        let account = if let Ok(mut account) = self.conn.get_account(account_mail) {
            if account.cert.primary_key().with_policy(policy, now).is_ok() {
                return Ok(());
            }
            let (cert, _) = self.gen_cert(account_mail, now)?;

            account.cert = cert;
            self.conn.update_account(&account)?;
            account
        } else {
            let (cert, _) = self.gen_cert(account_mail, now)?;

            let account = Account::new(account_mail, cert);
            self.conn.insert_account(&account)?;
            account
        };

        // We insert our own account into the peers, this is so we can send encrypted emails
        // to our self and use it to make encrypted drafts
        self.update_peer_forceable(
            account_mail,
            account_mail,
            &account.cert,
            account.prefer,
            now.into(),
            false,
            true,
        )?;
        Ok(())
    }

    /// Update the when we last saw this email.
    /// * `account_mail` - The user account or optional None if we are in wildmode
    pub fn update_last_seen(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if now.cmp(&Utc::now()) == Ordering::Greater {
            return Err(anyhow::anyhow!("Date is in the future"));
        }

        let mut peer = self.peer(account_mail, peer_mail)?;

        peer.last_seen = now;

        self.conn.update_peer(&peer, account_mail.is_some())
    }

    /// Update the peer. If the data is older than what we currently have in the database
    /// no update is done.
    pub fn update_peer(
        &self,
        account_mail: &str,
        peer_mail: &str,
        key: &Cert,
        prefer: Prefer,
        effective_date: DateTime<Utc>,
        gossip: bool,
    ) -> Result<bool> {
        self.update_peer_forceable(
            account_mail,
            peer_mail,
            key,
            prefer,
            effective_date,
            gossip,
            false,
        )
    }

    // like update_peer but we can force updates. It's mostly used to install the peer associated
    // with the account.
    fn update_peer_forceable(
        &self,
        account_mail: &str,
        peer_mail: &str,
        key: &Cert,
        prefer: Prefer,
        effective_date: DateTime<Utc>,
        gossip: bool,
        force: bool,
    ) -> Result<bool> {
        if !force && account_mail == peer_mail {
            return Err(anyhow::anyhow!(
                "Updating the peer for your private key isn't allowed directly."
            ));
        }

        let peer = if self.wildmode {
            self.peer(None, Selector::Email(peer_mail))
        } else {
            self.peer(Some(account_mail), Selector::Email(peer_mail))
        };

        match peer {
            Err(_) => {
                let peer = Peer::new(peer_mail, account_mail, effective_date, key, gossip, prefer);
                self.conn.insert_peer(&peer)?;
                Ok(true)
            }
            Ok(mut peer) => {
                if !force && effective_date.cmp(&peer.last_seen) == Ordering::Less {
                    return Ok(false);
                }

                peer.last_seen = effective_date;

                if !gossip {
                    if force
                        || peer.timestamp.is_none()
                        || effective_date.cmp(&peer.timestamp.unwrap()) == Ordering::Greater
                    {
                        peer.timestamp = Some(effective_date);
                        peer.cert = Some(Cow::Borrowed(key));
                        peer.account = account_mail.to_owned();
                    }
                } else if force
                    || peer.gossip_timestamp.is_none()
                    || effective_date.cmp(&peer.gossip_timestamp.unwrap()) == Ordering::Greater
                {
                    peer.gossip_timestamp = Some(effective_date);
                    peer.gossip_cert = Some(Cow::Borrowed(key));
                    peer.account = account_mail.to_owned();
                }
                self.conn.update_peer(&peer, self.wildmode)?;

                Ok(true)
            }
        }
    }

    /// recommend tells the user whether or not it's a good idea to encrypt to a receiver.
    /// This should be called once for each receiver. Autoencrypt is more eager to
    /// encrypt when replying to encrypted emails.
    /// * `account_mail` - The user account or optional None if we are in wildmode
    /// * `peer_mail` - Peer we want to check if it's safe to encrypt to.
    /// * `reply_to_encrypted` - If we reply to an encrypted email.
    /// * `prefer` - our account setting.
    pub fn recommend(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        if let Ok(peer) = self.peer(account_mail, Selector::Email(peer_mail)) {
            let pre = peer.preliminary_recommend(policy);
            if pre.encryptable() && reply_to_encrypted {
                return UIRecommendation::Encrypt;
            }
            if pre.preferable() && peer.prefer.encrypt() && prefer.encrypt() {
                return UIRecommendation::Encrypt;
            }
            return pre;
        }
        UIRecommendation::Disable
    }

    pub fn multi_recommend(
        &self,
        account_mail: Option<&str>,
        peers_mail: &[&str],
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        peers_mail
            .iter()
            .map(|m| self.recommend(account_mail, m, policy, reply_to_encrypted, prefer))
            .sum()
    }

    /// Generate a autocryptheader to be inserted into a email header with our public key.
    pub fn header(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        prefer: Prefer,
    ) -> Result<AutocryptHeader> {
        let account = self.account(account_mail)?;

        AutocryptHeader::new_sender(policy, &account.cert, account_mail, prefer)
    }

    /// Generate a autocryptheader to be inserted into a email header
    /// with gossip information about peers. Gossip is used to spread keys faster.
    /// This should be called once for each gossip header we want spread.
    /// * `account_mail` - The user account or optional None if we are in wildmode
    /// * `peer_mail` - peer we want to generate gossip for
    pub fn gossip_header(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        policy: &dyn Policy,
    ) -> Result<AutocryptHeader> {
        let peer = self.peer(account_mail, Selector::Email(peer_mail))?;

        if let Some(ref cert) = peer.cert {
            if let Ok(mut header) = AutocryptHeader::new_sender(policy, cert, peer_mail, None) {
                header.header_type = AutocryptHeaderType::Gossip;
                return Ok(header);
            }
        }
        if let Some(ref cert) = peer.gossip_cert {
            if let Ok(mut header) = AutocryptHeader::new_sender(policy, cert, peer_mail, None) {
                header.header_type = AutocryptHeaderType::Gossip;
                return Ok(header);
            }
        }
        Err(anyhow::anyhow!("Can't find key to create gossip data"))
    }

    /// Make a setup message. Setup messages are used to transfer your private key
    /// from one autocrypt implementation to another. Making it easier to change MUA.
    pub fn setup_message(&self, account_mail: &str) -> Result<AutocryptSetupMessage> {
        let account = self.account(account_mail)?;

        if let Some(ref password) = self.password {
            let open = remove_password(account.cert, password)?;
            Ok(AutocryptSetupMessage::new(open))
        } else {
            Ok(AutocryptSetupMessage::new(account.cert))
        }
    }

    /// Install a setup message into the system. If the key is usable we install the key.
    /// If the account doesn't exist, it's created.
    /// It doesn't care if the cert is older than the current, it will be overwritten anyways.
    pub fn install_message(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        mut message: AutocryptSetupMessageParser,
        password: &Password,
    ) -> Result<()> {
        message.decrypt(password)?;
        let decrypted = message.parse()?;
        let mut cert = decrypted.into_cert();

        let now = SystemTime::now();
        cert.primary_key().with_policy(policy, now)?;

        if let Some(ref password) = self.password {
            cert = set_password(cert, password)?
        }

        let account = if let Ok(mut account) = self.account(account_mail) {
            // We don't check which cert is newer etc.
            // We expect the user to know what he/she is doing
            account.cert = cert;
            account
        } else {
            Account::new(account_mail, cert)
        };
        self.conn.update_account(&account)?;
        self.update_peer_forceable(
            account_mail,
            account_mail,
            &account.cert,
            account.prefer,
            now.into(),
            false,
            true,
        )?;
        Ok(())
    }

    /// Encrypt input
    /// * `account_mail` - our email address. Used to sign the email and to
    /// fetch peers if we're not in wildmode
    /// * `peers` - email address to the peers we want to send email to.
    pub fn encrypt(
        &self,
        policy: &dyn Policy,
        canonicalized_mail: &str,
        peers: &[&str],
        input: &mut (dyn Read + Send + Sync),
        output: &mut (dyn Write + Send + Sync),
    ) -> Result<()> {
        if peers.is_empty() {
            return Err(anyhow::anyhow!("No recipient"));
        }
        let mut fetched_peers: Vec<Peer> = Vec::new();
        let message = stream::Message::new(output);

        let mut recipient_subkeys: Vec<Recipient> = Vec::new();
        let account = self.account(canonicalized_mail)?;
        for rep in peers.iter() {
            let peer = if self.wildmode {
                self.peer(None, Selector::Email(rep))?
            } else {
                self.peer(Some(canonicalized_mail), Selector::Email(rep))?
            };
            fetched_peers.push(peer);
        }

        for peer in fetched_peers.iter() {
            let key = peer.get_recipient(policy)?;
            recipient_subkeys.push(key);
        }

        let message = Armorer::new(message).build()?;
        let encryptor = Encryptor::for_recipients(message, recipient_subkeys);
        let mut sink = encryptor.build()?;
        sink = Compressor::new(sink)
            .algo(CompressionAlgorithm::Zlib)
            .build()?;

        let signing_key = account
            .cert
            .keys()
            .secret()
            .with_policy(policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No key for signing found"))?
            .key()
            .clone();

        let secret = signing_key
            .optional_secret()
            .ok_or_else(|| anyhow::anyhow!("No secret signing key found"))?;

        let signing_keypair = match secret {
            Unencrypted(_) => signing_key.into_keypair(),
            Encrypted(ref e) => {
                if let Some(ref password) = self.password {
                    let res = e.decrypt(signing_key.pk_algo(), password)?;
                    crypto::KeyPair::new(signing_key.into(), res)
                } else {
                    return Err(anyhow::anyhow!("Key is encrypted but no password supplied"));
                }
            }
        }?;

        let signer = Signer::new(sink, signing_keypair);
        sink = signer.build()?;

        let mut literal_writer = LiteralWriter::new(sink)
            .build()
            .context("Failed to create literal writer")?;

        // Finally, copy stdin to our writer stack to encrypt the data.
        io::copy(input, &mut literal_writer).context("Failed to encrypt")?;

        literal_writer.finalize().context("Failed to encrypt")?;

        Ok(())
    }

    /// Decrypt input
    /// * `account_mail` - our email address. Used to decrypt email and to
    /// fetch peers for verify signatures, if we're not in wildmode.
    pub fn decrypt<S>(
        &self,
        policy: &dyn Policy,
        account_mail: &str,
        input: &mut (dyn Read + Send + Sync),
        output: &mut (dyn Write + Send + Sync),
        sk: S,
    ) -> Result<()>
    where
        S: Into<Option<SessionKey>>,
    {
        let account = self.account(account_mail)?;

        let account_mail = if self.wildmode {
            None
        } else {
            Some(account_mail)
        };

        let helper = DHelper::new(self, policy, account_mail, account.cert, sk.into());
        let mut decryptor = DecryptorBuilder::from_reader(input)?
            .with_policy(policy, None, helper)
            .context("Decryption failed")?;

        io::copy(&mut decryptor, output)?;

        // let helper = decryptor.into_helper();
        // helper.result.set_signatures(&helper.helper.list);
        Ok(())
    }

    /// Verify an email, since autocrypt is mainly for encrypting/decrypting emails
    /// and decrypt checks signatures, this function is rarely used.
    /// * `account_mail` - our email address. Used to decrypt email and to
    /// fetch peers for verify signatures, if we're not in wildmode
    pub fn verify(
        &self,
        policy: &dyn Policy,
        account_mail: Option<&str>,
        input: &mut (dyn io::Read + Send + Sync),
        sigstream: Option<&mut (dyn io::Read + Send + Sync)>,
        output: Option<&mut (dyn io::Write + Send + Sync)>,
    ) -> Result<()> {
        check_mode!(self, account_mail);

        let helper = VHelper::new(self, account_mail);
        let _helper = if let Some(dsig) = sigstream {
            let mut v =
                DetachedVerifierBuilder::from_reader(dsig)?.with_policy(policy, None, helper)?;
            v.verify_reader(input)?;
            v.into_helper()
        } else {
            let mut v = VerifierBuilder::from_reader(input)?.with_policy(policy, None, helper)?;
            if let Some(output) = output {
                io::copy(&mut v, output)?;
                v.into_helper()
            } else {
                return Err(anyhow::anyhow!("None detach but no output stream"));
            }
        };

        Ok(())
    }
}

#[cfg(all(test, feature = "rusqlite"))]
mod tests {
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::cert::CipherSuite;
    use sequoia_openpgp::packet::Signature;
    use sequoia_openpgp::types::KeyFlags;
    use sequoia_openpgp::Cert;

    use chrono::{Duration, Utc};
    use std::str::from_utf8;
    use std::time::SystemTime;

    use sequoia_openpgp::policy::StandardPolicy;

    use crate::peer::Peer;
    use crate::peer::Prefer;
    use crate::rusqlite::SqliteDriver;
    use crate::store::SqlDriver;
    use crate::store::UIRecommendation;

    use crate::store::AutocryptStore;

    type Result<T> = sequoia_openpgp::Result<T>;

    static OUR: &'static str = "art.vandelay@vandelayindustries.com";
    static PEER1: &'static str = "regina.phalange@friends.com";
    static PEER2: &'static str = "ken.adams@friends.com";

    #[derive(PartialEq)]
    enum Mode {
        Seen,
        Gossip,
        _Both, // If we want both seen and gossip (todo)
    }

    fn test_db() -> AutocryptStore<SqliteDriver> {
        let conn = SqliteDriver::new(":memory:").unwrap();
        conn.setup().unwrap();
        AutocryptStore::new(conn, Some("hunter2"), false).unwrap()
    }

    fn gen_cert(canonicalized_mail: &str, now: SystemTime) -> Result<(Cert, Signature)> {
        let mut builder = CertBuilder::new();
        builder = builder.add_userid(canonicalized_mail);
        builder = builder.set_creation_time(now);

        builder = builder.set_validity_period(None);

        // builder = builder.set_validity_period(
        //     Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),

        // which one to use?
        // builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        builder = builder.set_cipher_suite(CipherSuite::Cv25519);

        builder = builder.add_subkey(KeyFlags::empty().set_transport_encryption(), None, None);

        builder.generate()
    }

    fn gen_peer(
        ctx: &AutocryptStore<SqliteDriver>,
        account_mail: &str,
        canonicalized_mail: &str,
        mode: Mode,
        prefer: Prefer,
    ) -> Result<()> {
        let now = SystemTime::now();

        let (cert, _) = gen_cert(canonicalized_mail, now)?;

        // Since we don't we don't we don't do as as_tsk() in insert_peer, we won't write the
        // private key
        let peer = Peer::new(
            canonicalized_mail,
            account_mail,
            Utc::now(),
            &cert,
            mode == Mode::Gossip,
            prefer,
        );
        ctx.conn.insert_peer(&peer).unwrap();

        Ok(())
    }

    #[test]
    fn test_gen_key() {
        let ctx = test_db();
        let policy = StandardPolicy::new();

        ctx.update_private_key(&policy, OUR).unwrap();
        let acc = ctx.conn.get_account(OUR).unwrap();

        // check stuff in acc
        ctx.update_private_key(&policy, OUR).unwrap();
        let acc2 = ctx.conn.get_account(OUR).unwrap();

        assert_eq!(acc, acc2);

        // check that PEER1 doesn't return anything
        if let Ok(_) = ctx.conn.get_account(PEER1.into()) {
            assert!(true, "PEER1 shouldn't be in the db!")
        }

        ctx.conn.delete_account(OUR, None).unwrap();
    }

    #[test]
    fn test_gen_peer() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        gen_peer(&ctx, &account.mail, PEER2, Mode::Seen, Prefer::Mutual).unwrap();

        let peer1 = ctx.conn.get_peer(Some(OUR), PEER1.into()).unwrap();
        let peer2 = ctx.conn.get_peer(Some(OUR), PEER2.into()).unwrap();

        assert_eq!(peer1.mail, PEER1);
        assert_eq!(peer2.mail, PEER2);

        assert_ne!(peer1, peer2);
    }

    #[test]
    fn test_update_peer() {
        let policy = StandardPolicy::new();

        let ctx = test_db();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let now = Utc::now();

        let peer1 = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();

        let (cert, _) = gen_cert(PEER1, now.into()).unwrap();

        ctx.update_peer(
            &account.mail,
            PEER1,
            &cert,
            Prefer::Nopreference,
            Utc::now(),
            true,
        )
        .unwrap();

        let updated = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();

        assert_ne!(peer1, updated);

        ctx.update_peer(
            &account.mail,
            PEER1,
            &cert,
            Prefer::Nopreference,
            Utc::now(),
            false,
        )
        .unwrap();
        let replaced = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();

        assert_ne!(replaced, updated)
    }

    #[test]
    fn test_update_old_peer_data() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let old_peer = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();

        let past = Utc::now() - Duration::days(150);
        let (cert, _) = gen_cert(PEER1, past.into()).unwrap();

        ctx.update_peer(
            &account.mail,
            PEER1,
            &cert,
            Prefer::Nopreference,
            past,
            false,
        )
        .unwrap();

        let same_peer = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();
        assert_eq!(old_peer, same_peer);
    }

    #[test]
    fn test_update_seen() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        let now = SystemTime::now();
        let (cert, _) = gen_cert(PEER1, now).unwrap();

        // we do this manually because we want to set an old date
        let now = Utc::now() - Duration::days(1);
        let peer = Peer::new(PEER1, &account.mail, now, &cert, false, Prefer::Mutual);

        ctx.conn.insert_peer(&peer).unwrap();

        let before = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();

        let future = Utc::now();
        ctx.update_last_seen(Some(&account.mail), PEER1, future)
            .unwrap();

        let peer = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();
        assert_ne!(before.last_seen, peer.last_seen);
    }

    #[test]
    fn test_update_seen_old() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        let peer = ctx
            .conn
            .get_peer(Some(&account.mail), PEER1.into())
            .unwrap();

        let history = Utc::now() - Duration::days(150);

        ctx.update_last_seen(Some(&account.mail), PEER1, history)
            .unwrap();

        assert_ne!(history, peer.last_seen);
    }

    #[test]
    fn test_delete_peer() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        ctx.conn.delete_peer(Some(OUR), PEER1).unwrap();
    }

    #[test]
    fn test_encrypt() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let input = "This is a small  to test encryption";
        let mut output: Vec<u8> = vec![];
        ctx.encrypt(&policy, OUR, &[PEER1], &mut input.as_bytes(), &mut output)
            .unwrap();
    }

    #[test]
    fn test_decrypt() {
        let ctx = test_db();

        let policy = StandardPolicy::new();

        ctx.update_private_key(&policy, OUR).unwrap();

        let input = "This is a small  to test encryption";

        let mut middle: Vec<u8> = vec![];
        ctx.encrypt(&policy, OUR, &[OUR], &mut input.as_bytes(), &mut middle)
            .unwrap();

        let mut output: Vec<u8> = vec![];
        let mut middle: &[u8] = &middle;

        ctx.decrypt(&policy, OUR, &mut middle, &mut output, None)
            .unwrap();

        let decrypted = from_utf8(&output).unwrap();

        assert_eq!(input, decrypted);
    }

    // #[test]
    // fn test_verify() {
    //     let ctx = test_db();
    //     let policy = StandardPolicy::new();
    //
    //     ctx.update_private_key(&policy, OUR).unwrap();
    //     gen_peer(&ctx, OUR, Mode::Seen, true).unwrap();
    //
    //     let input = "This is a small  to test encryption";
    //
    //     let mut middle: Vec<u8> = vec![];
    //     ctx.encrypt(&policy, OUR, &[PEER1], &mut input.as_bytes(), &mut middle).unwrap();
    //
    //     let mut output: Vec<u8> = vec![];
    //     let mut middle: &[u8] = &middle;
    //
    //     ctx.decrypt(&policy, OUR, &mut middle, &mut output, None).unwrap();
    //
    //     let decrypted = from_utf8(&output).unwrap();
    //
    //     // assert_eq!(input, decrypted);
    // }

    #[test]
    fn test_recommend_available() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        assert_eq!(
            ctx.recommend(Some(OUR), PEER1, &policy, false, Prefer::Mutual),
            UIRecommendation::Encrypt
        );
    }

    #[test]
    fn test_recommend_disable() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        assert_eq!(
            ctx.recommend(Some(OUR), PEER1, &policy, false, Prefer::Mutual),
            UIRecommendation::Disable
        );
        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        assert_eq!(
            ctx.recommend(Some(OUR), PEER2, &policy, false, Prefer::Mutual),
            UIRecommendation::Disable
        );
    }

    #[test]
    fn test_recommond_gossip() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.conn.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Gossip, Prefer::Mutual).unwrap();

        assert_eq!(
            ctx.recommend(Some(OUR), PEER1, &policy, false, Prefer::Mutual),
            UIRecommendation::Discourage
        )
    }
}
