extern crate sequoia_openpgp as openpgp;
use std::{
    borrow::Cow,
    cmp::Ordering,
    io::{self, Read, Write},
    marker::PhantomData,
    time::SystemTime,
};

use crate::{
    account::Account,
    driver::{Selector, SqlDriver, WildDriver},
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

pub struct Wild;

pub struct Strict;

pub struct AutocryptStore<T: SqlDriver, Mode> {
    pub(crate) password: Option<Password>,
    pub(crate) conn: T,
    mode: std::marker::PhantomData<Mode>,
}

// macro_rules! check_mode {
//     ($self:ident, $account_mail:expr) => {
//         if !$self.wildmode && $account_mail.is_none() {
//             return Err(anyhow::anyhow!(
//                 "You need to specify an account when the database isn't running in wildcard mode"
//             ));
//         }
//     };
// }
//
impl<T: SqlDriver, M> AutocryptStore<T, M> {
    pub fn new(conn: T, password: Option<&str>) -> Result<AutocryptStore<T, M>> {
        Ok(AutocryptStore {
            password: password.map(Password::from),
            conn,
            mode: PhantomData,
        })
    }
    fn account(&self, account_mail: &str) -> Result<Account> {
        self.conn.get_account(account_mail)
    }

    #[cfg(feature = "cert-d")]
    /// Get a cert for an account
    pub fn account_cert(&self, account_mail: &str) -> Result<Cert> {
        let account = self.account(account_mail)?;
        Ok(account.cert)
    }

    /// Set the prefer setting for an account
    pub fn set_prefer(&self, account_mail: &str, prefer: Prefer) -> Result<()> {
        let mut account = self.conn.get_account(account_mail)?;
        account.prefer = prefer;
        self.conn.insert_account(&account)
    }

    /// Get the prefer setting for an account
    pub fn prefer(&self, account_mail: &str) -> Result<Prefer> {
        let account = self.conn.get_account(account_mail)?;
        Ok(account.prefer)
    }

    /// Set enable for an account
    /// These are just internal settings and doesn't effect runtime.
    /// Functions such as recommend does not check the enable and it's up
    /// the user to do so.
    pub fn set_enable(&self, account_mail: &str, enable: bool) -> Result<()> {
        let mut account = self.conn.get_account(account_mail)?;
        account.enable = enable;
        self.conn.insert_account(&account)
    }

    /// Get enable for an account
    pub fn enable(&self, account_mail: &str) -> Result<bool> {
        let account = self.conn.get_account(account_mail)?;
        Ok(account.enable)
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
        builder = builder.add_subkey(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            None,
            None,
        );

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

        let peer = self
            .conn
            .get_peer(account_mail, Selector::Email(account_mail))
            .ok();

        // We insert our own account into the peers, this is so we can send encrypted emails
        // to our self and use it to make encrypted drafts
        self.update_peer_forceable(
            account_mail,
            account_mail,
            peer,
            &account.cert,
            account.prefer,
            now.into(),
            false,
            true,
        )?;
        Ok(())
    }

    // like update_peer but we can force updates. It's mostly used to install the peer associated
    // with the account.
    fn update_peer_forceable(
        &self,
        account_mail: &str,
        peer_mail: &str,
        peer: Option<Peer>,
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

        match peer {
            None => {
                let peer = Peer::new(peer_mail, account_mail, effective_date, key, gossip, prefer);
                self.conn.insert_peer(&peer)?;
                Ok(true)
            }
            Some(mut peer) => {
                if !force && effective_date.cmp(&peer.last_seen) == Ordering::Less {
                    return Ok(false);
                }

                peer.last_seen = effective_date;

                if !gossip {
                    if force
                        // either we don't have a timestamp or it's older
                        || peer.timestamp.is_none()
                        || effective_date.cmp(&peer.timestamp.unwrap()) == Ordering::Greater
                    {
                        peer.timestamp = Some(effective_date);
                        peer.cert = Some(Cow::Borrowed(key));
                        // we now transfer the peer to the new account
                        peer.account = account_mail.to_owned();
                    }
                } else if force
                    // either we don't have a timestamp or it's older
                    || peer.gossip_timestamp.is_none()
                    || effective_date.cmp(&peer.gossip_timestamp.unwrap()) == Ordering::Greater
                {
                    peer.gossip_timestamp = Some(effective_date);
                    peer.gossip_cert = Some(Cow::Borrowed(key));
                    // we now transfer the peer to the new account
                    peer.account = account_mail.to_owned();
                    peer.prefer = prefer;
                }
                self.conn.update_peer(&peer)?;

                Ok(true)
            }
        }
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

    /// Generate an autocryptheader to be inserted into a email header with our public key.
    pub fn header(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        prefer: Prefer,
    ) -> Result<AutocryptHeader> {
        let account = self.account(account_mail)?;

        AutocryptHeader::new_sender(policy, &account.cert, account_mail, prefer)
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

        let peer = self
            .conn
            .get_peer(account_mail, Selector::Email(account_mail))
            .ok();

        self.update_peer_forceable(
            account_mail,
            account_mail,
            peer,
            &account.cert,
            account.prefer,
            now.into(),
            false,
            true,
        )?;
        Ok(())
    }

    fn gossip_helper(&self, peer: &Peer, policy: &dyn Policy) -> Result<AutocryptHeader> {
        if let Some(ref cert) = peer.cert {
            if let Ok(mut header) = AutocryptHeader::new_sender(policy, cert, &peer.mail, None) {
                header.header_type = AutocryptHeaderType::Gossip;
                return Ok(header);
            }
        }
        if let Some(ref cert) = peer.gossip_cert {
            if let Ok(mut header) = AutocryptHeader::new_sender(policy, cert, &peer.mail, None) {
                header.header_type = AutocryptHeaderType::Gossip;
                return Ok(header);
            }
        }
        Err(anyhow::anyhow!("Can't find key to create gossip data"))
    }

    fn verify_helper(
        &self,
        helper: VHelper<T, M>,
        policy: &dyn Policy,
        input: &mut (dyn io::Read + Send + Sync),
        sigstream: Option<&mut (dyn io::Read + Send + Sync)>,
        output: Option<&mut (dyn io::Write + Send + Sync)>,
    ) -> Result<()> {
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

    fn encrypt_helper(
        &self,
        policy: &dyn Policy,
        account_mail: &str,
        peers: &[Peer],
        input: &mut (dyn Read + Send + Sync),
        output: &mut (dyn Write + Send + Sync),
    ) -> Result<()> {
        let account = self.account(account_mail)?;

        let message = stream::Message::new(output);

        let mut recipient_subkeys: Vec<Recipient> = Vec::new();

        for peer in peers.iter() {
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

    fn decrypt_helper(
        &self,
        helper: DHelper<T, M>,
        policy: &dyn Policy,
        input: &mut (dyn Read + Send + Sync),
        output: &mut (dyn Write + Send + Sync),
    ) -> Result<()> {
        let mut decryptor = DecryptorBuilder::from_reader(input)?
            .with_policy(policy, None, helper)
            .context("Decryption failed")?;

        io::copy(&mut decryptor, output)?;

        // let helper = decryptor.into_helper();
        // helper.result.set_signatures(&helper.helper.list);
        Ok(())
    }

    fn recommend_helper(
        &self,
        peer: &Option<Peer>,
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        if let Some(peer) = peer {
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
}

/// An autocrypt store, responsible for key storage.
///
/// AutocryptStore stores your pgp keys and encrypts and decrypts data.
/// AutocryptStore does not contain an sign function because it's not in the scope of autocrypt.
///
/// All arguments that accept on or more emails expect the emails to be canonicalized. If not
/// canonicalized, comparisons might fail.
impl<T: SqlDriver> AutocryptStore<T, Strict> {
    // pub fn new(conn: T, password: Option<&str>) -> Result<Self> {
    //     Ok(AutocryptStore {
    //         password: password.map(Password::from),
    //         conn,
    //         mode: Default::default(),
    //     })
    // }

    fn peer<'a, S>(&self, account_mail: &str, selector: S) -> Result<Peer>
    where
        S: Into<Selector<'a>>,
    {
        self.conn.get_peer(account_mail, selector.into())
    }

    #[cfg(feature = "cert-d")]
    /// Get cert and gossip cert for a peer
    /// * `account_mail` - The user account
    /// * `mail` - The peer email account
    pub fn peer_cert(
        &self,
        account_mail: Option<&str>,
        mail: &str,
    ) -> Result<(Option<Cert>, Option<Cert>)> {
        let peer = self.peer(account_mail, mail)?;
        Ok((
            peer.cert.map(|c| c.into_owned()),
            peer.gossip_cert.map(|c| c.into_owned()),
        ))
    }

    /// Update the when we last saw this peer. If the date is older than our
    /// current value, nothing happens.
    /// * `account_mail` - The user account
    /// * `peer_mail` - Peer we want to update
    /// * `effective_date` - The date we want to update to. This should be the date from the email.
    pub fn update_last_seen(
        &self,
        account_mail: &str,
        peer_mail: &str,
        effective_date: DateTime<Utc>,
    ) -> Result<()> {
        if effective_date.cmp(&Utc::now()) == Ordering::Greater {
            return Err(anyhow::anyhow!("Date is in the future"));
        }

        let mut peer = self.peer(account_mail, peer_mail)?;

        peer.last_seen = effective_date;

        self.conn.update_peer(&peer)
    }

    pub fn update_peer(
        &self,
        account_mail: &str,
        peer_mail: &str,
        key: &Cert,
        prefer: Prefer,
        effective_date: DateTime<Utc>,
        gossip: bool,
    ) -> Result<bool> {
        let peer = self.peer(account_mail, peer_mail).ok();
        self.update_peer_forceable(
            account_mail,
            peer_mail,
            peer,
            key,
            prefer,
            effective_date,
            gossip,
            false,
        )
    }

    /// recommend tells the user whether or not it's a good idea to encrypt to a receiver.
    /// This should be called once for each receiver. Autoencrypt is more eager to
    /// encrypt when replying to encrypted emails.
    /// * `account_mail` - The user account
    /// * `peer_mail` - Peer we want to check if it's safe to encrypt to.
    /// * `reply_to_encrypted` - If we reply to an encrypted email.
    /// * `prefer` - our account setting.
    pub fn recommend(
        &self,
        account_mail: &str,
        peer_mail: &str,
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        let peer = self.peer(account_mail, Selector::Email(peer_mail)).ok();
        self.recommend_helper(&peer, policy, reply_to_encrypted, prefer)
    }

    /// multi_recommend runs recommend on multiple peers.
    /// * `account_mail` - The user account
    /// * `peers_mail` - Peers we want to check if it's safe to encrypt to.
    /// * `reply_to_encrypted` - If we reply to an encrypted email.
    /// * `prefer` - our account setting.
    pub fn multi_recommend(
        &self,
        account_mail: &str,
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

    /// Generate a autocryptheader to be inserted into a email header
    /// with gossip information about peers. Gossip is used to spread keys faster.
    /// This should be called once for each gossip header we want spread.
    /// * `account_mail` - The user account
    /// * `peer_mail` - peer we want to generate gossip for
    pub fn gossip_header(
        &self,
        account_mail: &str,
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

    /// Encrypt input. If we are in wildmode, we fetch peers from all accounts,
    /// otherwise we are limited to the peers associated with the account
    /// * `peers` - email address to the peers we want to send email to.
    pub fn encrypt(
        &self,
        policy: &dyn Policy,
        account_mail: &str,
        peers: &[&str],
        input: &mut (dyn Read + Send + Sync),
        output: &mut (dyn Write + Send + Sync),
    ) -> Result<()> {
        if peers.is_empty() {
            return Err(anyhow::anyhow!("No recipient"));
        }

        let mut fetched_peers: Vec<Peer> = Vec::new();

        for rep in peers.iter() {
            let peer = self.peer(account_mail, Selector::Email(rep))?;
            fetched_peers.push(peer);
        }
        self.encrypt_helper(policy, account_mail, &fetched_peers, input, output)
    }

    /// Decrypt input. This function will try to fetch peers needed to decrypt
    /// and verify the input. If we are in wildmode, we fetch peers from all
    /// accounts, otherwise we are limited to the peers associated with the account
    /// If we have a session key, we will try it first.
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

        let account_mail = Some(account_mail);
        let helper = DHelper::new(self, policy, account_mail, account.cert, sk.into());
        self.decrypt_helper(helper, policy, input, output)
    }

    /// Verify input. This function will try to fetch peers needed to verify
    /// the input. If we are in wildmode, we fetch peers from all
    /// accounts, otherwise we are limited to the peers associated with the account
    /// Since autocrypt is mainly for encrypting/decrypting emails
    /// and decrypt checks signatures, this function is rarely used.
    pub fn verify(
        &self,
        policy: &dyn Policy,
        account_mail: &str,
        input: &mut (dyn io::Read + Send + Sync),
        sigstream: Option<&mut (dyn io::Read + Send + Sync)>,
        output: Option<&mut (dyn io::Write + Send + Sync)>,
    ) -> Result<()> {
        let helper = VHelper::new(self, Some(account_mail));
        self.verify_helper(helper, policy, input, sigstream, output)
    }
}

impl<T: SqlDriver + WildDriver> AutocryptStore<T, Wild> {
    // pub fn new(conn: T, password: Option<&str>) -> Result<Self> {
    //     Ok(AutocryptStore {
    //         password: password.map(Password::from),
    //         conn,
    //         mode: Default::default(),
    //     })
    // }

    fn peer<'a, S>(&self, selector: S) -> Result<Peer>
    where
        S: Into<Selector<'a>>,
    {
        self.conn.get_wild_peer(selector.into())
    }

    #[cfg(feature = "cert-d")]
    /// Get cert and gossip cert for a peer
    /// * `account_mail` - The user account
    /// * `mail` - The peer email account
    pub fn peer_cert(
        &self,
        account_mail: Option<&str>,
        mail: &str,
    ) -> Result<(Option<Cert>, Option<Cert>)> {
        let peer = self.peer(account_mail, mail)?;
        Ok((
            peer.cert.map(|c| c.into_owned()),
            peer.gossip_cert.map(|c| c.into_owned()),
        ))
    }

    /// Update the when we last saw this peer. If the date is older than our
    /// current value, nothing happens.
    /// * `peer_mail` - Peer we want to update
    /// * `effective_date` - The date we want to update to. This should be the date from the email.
    pub fn update_last_seen(&self, peer_mail: &str, effective_date: DateTime<Utc>) -> Result<()> {
        if effective_date.cmp(&Utc::now()) == Ordering::Greater {
            return Err(anyhow::anyhow!("Date is in the future"));
        }

        let mut peer = self.peer(peer_mail)?;

        peer.last_seen = effective_date;

        self.conn.update_peer(&peer)
    }

    /// recommend tells the user whether or not it's a good idea to encrypt to a receiver.
    /// This should be called once for each receiver. Autoencrypt is more eager to
    /// encrypt when replying to encrypted emails.
    /// * `peer_mail` - Peer we want to check if it's safe to encrypt to.
    /// * `reply_to_encrypted` - If we reply to an encrypted email.
    /// * `prefer` - our account setting.
    pub fn recommend(
        &self,
        peer_mail: &str,
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        let peer = self.peer(Selector::Email(peer_mail)).ok();
        self.recommend_helper(&peer, policy, reply_to_encrypted, prefer)
    }

    /// multi_recommend runs recommend on multiple peers.
    /// * `peers_mail` - Peers we want to check if it's safe to encrypt to.
    /// * `reply_to_encrypted` - If we reply to an encrypted email.
    /// * `prefer` - our account setting.
    pub fn multi_recommend(
        &self,
        peers_mail: &[&str],
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        peers_mail
            .iter()
            .map(|m| self.recommend(m, policy, reply_to_encrypted, prefer))
            .sum()
    }

    /// Generate a autocryptheader to be inserted into a email header
    /// with gossip information about peers. Gossip is used to spread keys faster.
    /// This should be called once for each gossip header we want spread.
    /// * `peer_mail` - peer we want to generate gossip for
    pub fn gossip_header(&self, peer_mail: &str, policy: &dyn Policy) -> Result<AutocryptHeader> {
        let peer = self.peer(Selector::Email(peer_mail))?;
        self.gossip_helper(&peer, policy)
    }

    /// Encrypt input. If we are in wildmode, we fetch peers from all accounts,
    /// otherwise we are limited to the peers associated with the account
    /// * `peers` - email address to the peers we want to send email to.
    pub fn encrypt(
        &self,
        policy: &dyn Policy,
        account_mail: &str,
        peers: &[&str],
        input: &mut (dyn Read + Send + Sync),
        output: &mut (dyn Write + Send + Sync),
    ) -> Result<()> {
        if peers.is_empty() {
            return Err(anyhow::anyhow!("No recipient"));
        }

        let mut fetched_peers: Vec<Peer> = Vec::new();

        for rep in peers.iter() {
            let peer = self.peer(Selector::Email(rep))?;
            fetched_peers.push(peer);
        }
        self.encrypt_helper(policy, account_mail, &fetched_peers, input, output)
    }

    /// Decrypt input. This function will try to fetch peers needed to decrypt
    /// and verify the input. If we are in wildmode, we fetch peers from all
    /// accounts, otherwise we are limited to the peers associated with the account
    /// If we have a session key, we will try it first.
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

        let account_mail = Some(account_mail);
        let helper = DHelper::new(self, policy, account_mail, account.cert, sk.into());
        self.decrypt_helper(helper, policy, input, output)
    }

    /// Verify input. This function will try to fetch peers needed to verify
    /// the input. If we are in wildmode, we fetch peers from all
    /// accounts, otherwise we are limited to the peers associated with the account
    /// Since autocrypt is mainly for encrypting/decrypting emails
    /// and decrypt checks signatures, this function is rarely used.
    pub fn verify(
        &self,
        policy: &dyn Policy,
        input: &mut (dyn io::Read + Send + Sync),
        sigstream: Option<&mut (dyn io::Read + Send + Sync)>,
        output: Option<&mut (dyn io::Write + Send + Sync)>,
    ) -> Result<()> {
        let helper = VHelper::new(self, None);
        self.verify_helper(helper, policy, input, sigstream, output)
    }

    pub fn update_peer(
        &self,
        account_mail: &str,
        peer_mail: &str,
        key: &Cert,
        prefer: Prefer,
        effective_date: DateTime<Utc>,
        gossip: bool,
    ) -> Result<bool> {
        let peer = self.peer(peer_mail).ok();
        self.update_peer_forceable(
            account_mail,
            peer_mail,
            peer,
            key,
            prefer,
            effective_date,
            gossip,
            false,
        )
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

    use super::Strict;

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

    fn test_db() -> AutocryptStore<SqliteDriver, Strict> {
        let conn = SqliteDriver::new(":memory:").unwrap();
        conn.setup().unwrap();
        AutocryptStore::new(conn, Some("hunter2")).unwrap()
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
        ctx: &AutocryptStore<SqliteDriver, Strict>,
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
        let acc = ctx.account(OUR).unwrap();

        // check stuff in acc
        ctx.update_private_key(&policy, OUR).unwrap();
        let acc2 = ctx.account(OUR).unwrap();

        assert_eq!(acc, acc2);

        // check that PEER1 doesn't return anything
        if let Ok(_) = ctx.account(PEER1.into()) {
            assert!(true, "PEER1 shouldn't be in the db!")
        }

        ctx.conn.delete_account(OUR, None).unwrap();
    }

    #[test]
    fn test_gen_peer() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        gen_peer(&ctx, &account.mail, PEER2, Mode::Seen, Prefer::Mutual).unwrap();

        let peer1 = ctx.peer(OUR, PEER1).unwrap();
        let peer2 = ctx.peer(OUR, PEER2).unwrap();

        assert_eq!(peer1.mail, PEER1);
        assert_eq!(peer2.mail, PEER2);

        assert_ne!(peer1, peer2);
    }

    #[test]
    fn test_update_peer() {
        let policy = StandardPolicy::new();

        let ctx = test_db();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let now = Utc::now();

        let peer1 = ctx.peer(&account.mail, PEER1).unwrap();

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

        let updated = ctx.peer(&account.mail, PEER1).unwrap();

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
        let replaced = ctx.peer(&account.mail, PEER1).unwrap();

        assert_ne!(replaced, updated)
    }

    #[test]
    fn test_update_old_peer_data() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let old_peer = ctx.peer(&account.mail, PEER1).unwrap();

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

        let same_peer = ctx.peer(&account.mail, PEER1).unwrap();
        assert_eq!(old_peer, same_peer);
    }

    #[test]
    fn test_update_seen() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        let now = SystemTime::now();
        let (cert, _) = gen_cert(PEER1, now).unwrap();

        // we do this manually because we want to set an old date
        let now = Utc::now() - Duration::days(1);
        let peer = Peer::new(PEER1, &account.mail, now, &cert, false, Prefer::Mutual);

        ctx.conn.insert_peer(&peer).unwrap();

        let before = ctx.peer(&account.mail, PEER1).unwrap();

        let future = Utc::now();
        ctx.update_last_seen(&account.mail, PEER1, future).unwrap();

        let peer = ctx.peer(&account.mail, PEER1).unwrap();
        assert_ne!(before.last_seen, peer.last_seen);
    }

    #[test]
    fn test_update_seen_old() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        let peer = ctx.peer(&account.mail, PEER1).unwrap();

        let history = Utc::now() - Duration::days(150);

        ctx.update_last_seen(&account.mail, PEER1, history).unwrap();

        assert_ne!(history, peer.last_seen);
    }

    #[test]
    fn test_delete_peer() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        // let peer = ctx.peer(account_mail, selector)

        // ctx.conn.delete_peer(OUR, PEER1).unwrap();
    }

    #[test]
    fn test_encrypt() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

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
        let account = ctx.account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        assert_eq!(
            ctx.recommend(OUR, PEER1, &policy, false, Prefer::Mutual),
            UIRecommendation::Encrypt
        );
    }

    #[test]
    fn test_recommend_disable() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        assert_eq!(
            ctx.recommend(OUR, PEER1, &policy, false, Prefer::Mutual),
            UIRecommendation::Disable
        );
        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        assert_eq!(
            ctx.recommend(OUR, PEER2, &policy, false, Prefer::Mutual),
            UIRecommendation::Disable
        );
    }

    #[test]
    fn test_recommond_gossip() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Gossip, Prefer::Mutual).unwrap();

        assert_eq!(
            ctx.recommend(OUR, PEER1, &policy, false, Prefer::Mutual),
            UIRecommendation::Discourage
        )
    }
}
