extern crate sequoia_openpgp as openpgp;
use std::{time::SystemTime, cmp::Ordering, io::{Read, Write, self}, borrow::Cow};

use anyhow::Context;
use chrono::{Utc, DateTime, Duration};
use openpgp::{Cert, cert::{CertBuilder, CipherSuite, amalgamation::ValidateAmalgamation}, packet::Signature, types::{KeyFlags, CompressionAlgorithm}, crypto::{Password, self}, policy::Policy, serialize::stream::{self, Recipient, Armorer, Encryptor, Compressor, LiteralWriter, Signer}, parse::{stream::{DecryptorBuilder, DetachedVerifierBuilder, VerifierBuilder}, Parse}};
use sequoia_autocrypt::{AutocryptHeader, AutocryptHeaderType, AutocryptSetupMessage, AutocryptSetupMessageParser};
use crate::{Result, peer::{Peer, Prefer}, sq::SessionKey, account::Account, driver::{SqlDriver, Selector}};
use openpgp::packet::prelude::SecretKeyMaterial::{Unencrypted, Encrypted};
use crate::sq::{DHelper, VHelper};

// TODO:
// [ ] Return stuff from verify/decrypt
// [x] Get example to work
// [ ] Get ruslite into a feature
// [ ] Missing generic functions on store
// -- Remove stuff that shouldn't be public etc
// [ ] Create a driver for diesel
// [x] Genkey/import should insert a peer?
// [ ] Password doesn't really work atm
// Remove/change password, and import/export doesn't use password
// (Per account password?)

// TODO: (maybe later)
// [ ]  Docker file for setting up a selfhosted autocrypt

/// UIRecommendation represent whether or not we should encrypt an email.
/// Disable means that we shouldn't try to encrypt because it's likely people
/// won't be able to read it.
/// Discourage means that we have keys for all users to encrypt it but we don't
/// we are not sure they are still valid (we haven't seen them in long while,
/// we got them from gossip etc)
/// Available means all systems are go.
#[derive(Debug, PartialEq)]
pub enum UIRecommendation {
    Disable,
    Discourage,
    Available,
}

pub struct AutocryptStore<T: SqlDriver> {
    pub password: Option<Password>,
    pub wildmode: bool,
    pub conn: T,
}

macro_rules! check_mode {
    ($self:ident, $account_mail:expr) => {
        if !$self.wildmode && $account_mail.is_none() {
            return Err(anyhow::anyhow!(
                    "You need to specify an account when the database isn't running in wildcard mode"))
        }
    };
}

impl<T: SqlDriver> AutocryptStore<T> {
    pub fn new(conn: T, password: Option<&str>, wildmode: bool) -> Result<Self> {
        Ok(AutocryptStore { password: password.map(Password::from), conn, wildmode})
    }

    pub fn get_account(&self, canonicalized_mail: &str) -> Result<Account> {
        self.conn.get_account(canonicalized_mail)
    }

    pub fn get_peer<'a, S>(&self, account_mail: Option<&str>, selector: S) -> Result<Peer>
        where  S: Into<Selector<'a>> {
        check_mode!(self, account_mail);

        self.conn.get_peer(account_mail, selector.into())
    }

    fn gen_cert(&self, canonicalized_mail: &str, now: SystemTime) 
        -> Result<(Cert, Signature)> {

        let mut builder = CertBuilder::new();
        builder = builder.add_userid(canonicalized_mail);
        builder = builder.set_creation_time(now);

        builder = builder.set_validity_period(None);

        // builder = builder.set_validity_period(
        //     Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),

        // which one to use?
        // builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        builder = builder.set_cipher_suite(CipherSuite::Cv25519);

        builder = builder.add_signing_subkey();
        builder = builder.add_subkey(
            KeyFlags::empty()
            .set_transport_encryption(),
            None,
            None,
        );

        builder = builder.set_password(self.password.clone());

        builder.generate()
    }

    pub fn update_private_key(&self, policy: &dyn Policy, canonicalized_mail: &str) -> Result<()> {
        let now = SystemTime::now();

        // Check if we have a key, if that is the case, check if the key is ok.
        let account = if let Ok(mut account) = self.conn.get_account(canonicalized_mail) {
            if account.cert.primary_key().with_policy(policy, now).is_ok() {
                return Ok(())
            }
            let (cert, _) = self.gen_cert(canonicalized_mail, now)?;

            account.cert = cert;
            self.conn.update_account(&account)?;
            account
        } else {
            let (cert, _) = self.gen_cert(canonicalized_mail, now)?;
            
            let account = Account::new(canonicalized_mail, cert);
            self.conn.insert_account(&account)?;
            account
        };

        // We insert our own account into the peers, this is so we can send encrypted emails
        // to our self and use it to make encrypted drafts
        self._update_peer(canonicalized_mail, canonicalized_mail, &account.cert, 
            account.prefer, now.into(), false, true)?;
        Ok(())
    }

    pub fn update_last_seen(&self, account_mail: Option<&str>, canonicalized_mail: &str,
        now: DateTime<Utc>) -> Result<()> {

        if now.cmp(&Utc::now()) == Ordering::Greater {
            return Err(anyhow::anyhow!(
                    "Date is in the future"
            ))
        }

        let mut peer = self.get_peer(account_mail, Selector::Email(canonicalized_mail))?;

        peer.last_seen = now;
        
        println!("{:?} = {}", account_mail, peer.account);

        self.conn.update_peer(&peer, account_mail.is_some())
    }

    pub fn update_peer(&self, account_mail: &str, canonicalized_mail: &str, key: &Cert, 
        prefer: Prefer, effective_date: DateTime<Utc>, gossip: bool) -> Result<bool> {

        self._update_peer(account_mail, canonicalized_mail, key, prefer, effective_date, gossip, false)
    }

    fn _update_peer(&self, account_mail: &str, canonicalized_mail: &str, key: &Cert, 
        prefer: Prefer, effective_date: DateTime<Utc>, gossip: bool, force: bool) -> Result<bool> {

        if !force && account_mail == canonicalized_mail {
            return Err(anyhow::anyhow!(
                    "Updating the peer for your private key isn't allowed directly."))
        }

        let peer = if self.wildmode {
            self.get_peer(None, Selector::Email(canonicalized_mail))
        } else {
            self.get_peer(Some(account_mail), Selector::Email(canonicalized_mail))
        };

        match peer {
            Err(_) => {
                let peer = Peer::new(canonicalized_mail, account_mail, effective_date, key, gossip, prefer);
                self.conn.insert_peer(&peer)?;
                Ok(true)
            }
            Ok(mut peer) => {
                if !force && effective_date.cmp(&peer.last_seen) == Ordering::Less {
                    return Ok(false)
                }

                peer.last_seen = effective_date;

                if !gossip {
                    if force || peer.timestamp.is_none() || 
                        effective_date.cmp(&peer.timestamp.unwrap()) == Ordering::Greater {
                            peer.timestamp = Some(effective_date);
                            peer.cert = Some(Cow::Borrowed(key));
                            peer.account = account_mail.to_owned();
                    }
                } else if force || peer.gossip_timestamp.is_none() ||
                        effective_date.cmp(&peer.gossip_timestamp.unwrap()) == Ordering::Greater {
                            peer.gossip_timestamp = Some(effective_date);
                            peer.gossip_cert = Some(Cow::Borrowed(key));
                            peer.account = account_mail.to_owned();
                }
                self.conn.update_peer(&peer, self.wildmode)?;

                Ok(true)
            }
        }
    }
    
    pub fn recommend(&self, account_mail: Option<&str>, canonicalized_reciever: &str)
        -> UIRecommendation {
        if let Ok(peer) = self.get_peer(account_mail, Selector::Email(canonicalized_reciever)) {
            if peer.cert.is_some() {
                let stale = Utc::now() + Duration::days(35);
                if stale.cmp(&peer.last_seen) == Ordering::Less {
                    return UIRecommendation::Discourage;
                }
                return UIRecommendation::Available
            }
            if peer.gossip_cert.is_some() {
                return UIRecommendation::Discourage;
            }
        }
        UIRecommendation::Disable
    }

    pub fn header(&self, canonicalized_email: &str, policy: &dyn Policy, 
        prefer: Prefer) -> Result<AutocryptHeader> {
        let account = self.get_account(canonicalized_email)?;

        AutocryptHeader::new_sender(policy, &account.cert, canonicalized_email, prefer)
    }


    pub fn gossip_header(&self, our: Option<&str>, canonicalized_email: &str,
        policy: &dyn Policy) -> Result<AutocryptHeader> {

        let peer = self.get_peer(our, Selector::Email(canonicalized_email))?;

        if let Some(ref cert) = peer.cert {
            if let Ok(mut header) = 
                AutocryptHeader::new_sender(policy, cert, canonicalized_email, None) {

                header.header_type = AutocryptHeaderType::Gossip;
                return Ok(header)
            }
        }
        if let Some(ref cert) = peer.gossip_cert {
            if let Ok(mut header) = 
                AutocryptHeader::new_sender(policy, cert, canonicalized_email, None) {

                header.header_type = AutocryptHeaderType::Gossip;
                return Ok(header)
            }
        }
        Err(anyhow::anyhow!(
                "Can't find key to create gossip data"))
    }

    pub fn setup_message(&self, canonicalized_email: &str) -> Result<AutocryptSetupMessage> {
        let account = self.get_account(canonicalized_email)?;
        Ok(AutocryptSetupMessage::new(account.cert))
    }

    pub fn install_message(&self, canonicalized_mail: &str, policy: &dyn Policy,
        mut message: AutocryptSetupMessageParser, password: &Password) -> Result<()> {
        message.decrypt(password)?;
        let decrypted = message.parse()?;
        let cert = decrypted.into_cert();

        let now = SystemTime::now();
        cert.primary_key().with_policy(policy, now)?;

        let account = if let Ok(mut account) = self.get_account(canonicalized_mail) {
            // We don't check which cert is newer etc.
            // We expect the user to know what he/she is doing
            account.cert = cert;
            account
        } else {
            Account::new(canonicalized_mail, cert)
        };
        self.conn.update_account(&account)?;
        self._update_peer(canonicalized_mail, canonicalized_mail, &account.cert, 
            account.prefer, now.into(), false, true)?;
        Ok(())
    }

    // recipients needs to be a list of canonicalized emails
    pub fn encrypt(&self, policy: &dyn Policy,
        canonicalized_email: &str, recipients: &[&str],
        input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync))
        -> Result<()> {

        if recipients.is_empty() {
            return Err(anyhow::anyhow!(
                    "No recipient"));
        }
        let mut peers: Vec<Peer> = Vec::new();
        let message = stream::Message::new(output);

        let mut recipient_subkeys: Vec<Recipient> = Vec::new();
        let account = self.get_account(canonicalized_email)?;
        for rep in recipients.iter() {
            let peer = if self.wildmode {
                self.get_peer(None, Selector::Email(rep))?
            } else {
                self.get_peer(Some(canonicalized_email), Selector::Email(rep))?
            };
            peers.push(peer);
        }

        for peer in peers.iter() {
            let key = peer.get_recipient(policy)?;
            recipient_subkeys.push(key);
        }
        
        let message = Armorer::new(message).build()?;
        let encryptor = Encryptor::for_recipients(message, recipient_subkeys);
        let mut sink = encryptor.build()?;
        sink = Compressor::new(sink).algo(CompressionAlgorithm::Zlib).build()?;

        let signing_key = account.cert.keys().secret()
            .with_policy(policy, None).supported().alive().revoked(false).for_signing()
            .next().ok_or_else(||
                anyhow::anyhow!(
                    "No key for signing found")
                )?
            .key().clone();

        let secret = signing_key.optional_secret().ok_or_else(||
            anyhow::anyhow!("No secret signing key found")
        )?;

        let signing_keypair = match secret {
            Unencrypted(_) => {
                signing_key.into_keypair()
            }
            Encrypted(ref e) => {
                if let Some(ref password) = self.password {
                    let res = e.decrypt(signing_key.pk_algo(), password)?;
                    crypto::KeyPair::new(signing_key.into(), res)
                } else {
                    return Err(anyhow::anyhow!("Key is encrypted but no password supplied"))
                }
            }
        }?;

        let signer = Signer::new(sink, signing_keypair);
        sink = signer.build()?;

        let mut literal_writer = LiteralWriter::new(sink).build()
            .context("Failed to create literal writer")?;

            // Finally, copy stdin to our writer stack to encrypt the data.
            io::copy(input, &mut literal_writer)
                .context("Failed to encrypt")?;

            literal_writer.finalize()
                .context("Failed to encrypt")?;

        Ok(())
    }
    pub fn decrypt<S>(&self, policy: &dyn Policy, canonicalized_mail: &str,
        input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync),
        sk: S)
        -> Result<()> 
        where  S: Into<Option<SessionKey>>
    {

            let account = self.get_account(canonicalized_mail)?;

            let account_mail = if self.wildmode {
                None
            } else {
                Some(canonicalized_mail)
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

    pub fn verify(&self, policy: &dyn Policy, account_mail: Option<&str>, input: 
        &mut (dyn io::Read + Send + Sync), sigstream: Option<&mut (dyn io::Read + Send + Sync)>,
        output: Option<&mut (dyn io::Write + Send + Sync)>) -> Result<()> {

        let helper = VHelper::new(self, account_mail);
        let _helper = if let Some(dsig) = sigstream {
            let mut v = DetachedVerifierBuilder::from_reader(dsig)?
                .with_policy(policy, None, helper)?;
            v.verify_reader(input)?;
            v.into_helper()
        } else {
            let mut v = VerifierBuilder::from_reader(input)?
                .with_policy(policy, None, helper)?;
            if let Some(output) = output {
                io::copy(&mut v, output)?;
                v.into_helper()
            } else {
                return Err(anyhow::anyhow!("None detach but no output stream"))
            }
        };

        Ok(())
    }
}
