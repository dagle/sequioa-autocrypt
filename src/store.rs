extern crate sequoia_openpgp as openpgp;
use std::{path::PathBuf, time::SystemTime, cmp::Ordering, io::{Read, Write, self}, borrow::Cow};

use anyhow::Context;
use chrono::{Utc, DateTime, NaiveDateTime, Duration};
use openpgp::{Cert, cert::{CertParser, CertBuilder, CipherSuite, amalgamation::ValidateAmalgamation}, Fingerprint, packet::Signature, types::{KeyFlags, CompressionAlgorithm}, crypto::{Password, self}, policy::Policy, serialize::{stream::{self, Recipient, Armorer, Encryptor, Compressor, LiteralWriter, Signer}, SerializeInto, Marshal}, parse::{stream::{DecryptorBuilder, DetachedVerifierBuilder, VerifierBuilder}, Parse}};
use rusqlite::{Connection, params, Rows};
use sequoia_autocrypt::{AutocryptHeader, AutocryptHeaderType, AutocryptSetupMessage, AutocryptSetupMessageParser};
use crate::{Result, peer::{Peer, Prefer}, sq::SessionKey};
use openpgp::packet::prelude::SecretKeyMaterial::{Unencrypted, Encrypted};
use crate::sq::{DHelper, VHelper};

// TODO:
// [ ] Return stuff from verify/decrypt
// [ ] Feature: Account settings
// [ ] Change new to take a path and not a directory or a engine 
// [ ] Support a generic db engine (sqlx)
// [ ] Password doesn't really work atm
// Remove/change password, and import/export doesn't use password
// (Per account password?)

static DBNAME: &str = "autocrypt.db";

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

#[derive(PartialEq, Debug)]
pub struct Account {
    pub mail: String,
    pub cert: Cert,

    // If we want to save settings into the database. For some applications
    // you might want configure this in your normal settings rather
    // having it in the database.

    // #[cfg(feature = "account-settings")]
    pub prefer: Prefer,
    // #[cfg(feature = "account-settings")]
    pub enable: bool,
}

impl Account {
    fn new(mail: &str, cert: Cert) -> Self {
        // #[cfg(feature = "account-settings")]
        Account { mail: mail.to_owned(), cert, prefer: Prefer::Nopreference, enable: false }

        // #[cfg(not(feature = "account-settings"))]
        // Account { mail: mail.to_owned(), cert};

    }
}

pub fn setup(con: &Connection) -> Result<()> {
    // we create all fields even if we
    // don't use prefer and enable 
    // unless account-settings is enabled
    // is enabled
    let accountschema =
        "CREATE TABLE account (
            address text primary key not null, 
            key text,
            prefer int,
            enable int
            )";
    con.execute(accountschema, [])?;

    // should a peer be connect with an Account?
    let peerschema = 
        "CREATE TABLE peer (
            address text not null, 
            last_seen INT8, 
            timestamp INT8,
            key text,
            key_fpr,
            gossip_timestamp INT8,
            gossip_key text,
            gossip_key_fpr,
            prefer int,
            account text,
            FOREIGN KEY(account) REFERENCES account(address),
            PRIMARY KEY(address, account)
            )";

    con.execute(peerschema, [])?;
    Ok(())
}

// if we find one key for encryption, return true
macro_rules! get_time {
    ($field:expr) => {
        {
            let unix: Option<i64> = $field?;
            let ts: Option<DateTime<Utc>> = if let Some(unix) = unix {
                let nt = NaiveDateTime::from_timestamp_opt(unix, 0).ok_or_else(||
                    anyhow::anyhow!(
                        "Couldn't parse timestamp")
                )?;
                let dt = DateTime::<Utc>::from_utc(nt, Utc);
                Some(dt)
            } else {
                None
            };
            ts
        }
    }
}

pub struct AutocryptStore {
    pub password: Option<Password>,
    pub wildcard: bool,
    pub con: Connection,
}

macro_rules! peerstmt {
    ($selector:expr) => {
        concat!("SELECT
            address, 
            last_seen, 
            timestamp, 
            key, 
            gossip_timestamp, 
            gossip_key, 
            prefer,
            account
            FROM peer
            ", $selector)
    };
}

macro_rules! peer_fun {
    ($self:ident, $selector:expr, $($param:expr),+) => {
    {
        let mut selectstmt = $self.con.prepare(
            peerstmt!($selector))?;

        let mut rows = selectstmt.query(params![
            $($param),*
        ])?;
        Self::row_to_peer(&mut rows)
    }
    };
}

macro_rules! check_mode {
    ($self:ident, $account_mail:expr) => {
        if !$self.wildcard && $account_mail.is_none() {
            return Err(anyhow::anyhow!(
                    "You need to specify an account when the database isn't running in wildcard mode"))
        }
    };
}

impl AutocryptStore {
    pub fn new(path: &str, password: Option<&str>, wildcard: bool) -> Result<Self> {
        let mut dbpath = PathBuf::new();
        dbpath.push(path);
        dbpath.push(DBNAME);
        let con = Connection::open(dbpath)?;
        Ok(AutocryptStore { password: password.map(Password::from), con, wildcard})
    }

    pub fn get_account(&self, canonicalized_mail: &str) -> Result<Account> {
        let mut selectstmt = self.con.prepare(
            "SELECT
            address, 
            key, 
            prefer,
            enable
            FROM account 
            WHERE address = ?")?;

        let mut rows = selectstmt.query(params![
            canonicalized_mail
        ])?;

        if let Some(row) = rows.next()? {
            let mail: String = row.get(0)?;
            let keystr: String = row.get(1)?;
            let cert: Cert = CertParser::from_reader(keystr.as_bytes())?
                .find_map(|cert| cert.ok())
                .ok_or(anyhow::anyhow!("No valid key found for account"))?;

            let prefer: Prefer = row.get(2)?;
            let enable: bool = row.get(3)?;

            return Ok(Account {
                mail,
                cert,
                prefer,
                enable,
            })
        }
        return Err(anyhow::anyhow!("No Account found"));

    }
    fn row_to_peer<'a>(rows: &mut Rows) -> Result<Peer<'a>> {
        if let Some(row) = rows.next()? {
            let mail: String = row.get(0)?;
            let unix: i64 = row.get(1)?;
            let last_seen: DateTime<Utc> = {
                let nt = NaiveDateTime::from_timestamp_opt(unix, 0).ok_or_else(||
                    anyhow::anyhow!(
                        "Couldn't parse timestamp")
                )?;
                DateTime::<Utc>::from_utc(nt, Utc)
            };

            let timestamp = get_time!(row.get(2));
            let keystr: Option<String> = row.get(3)?;
            let key: Option<Cow<Cert>> = if let Some(keystr) = keystr {
                CertParser::from_reader(keystr.as_bytes())?.find_map(|cert| cert.ok())
                .map(Cow::Owned)
            } else {
                None
            };

            let gossip_timestamp = get_time!(row.get(2));
            let gossip_keystr: Option<String> = row.get(5)?;
            let gossip_key: Option<Cow<Cert>> = if let Some(keystr) = gossip_keystr {
                CertParser::from_reader(keystr.as_bytes())?.find_map(|cert| cert.ok())
                .map(Cow::Owned)
            } else {
                None
            };
            let prefer: Prefer = row.get(6)?;
            let account: String = row.get(7)?;

            return Ok(Peer {
                mail,
                account,
                last_seen,
                timestamp,
                cert: key,
                gossip_timestamp,
                gossip_cert: gossip_key,
                prefer,
            })
        }
        return Err(anyhow::anyhow!("No Peer found"));
    }

    pub fn get_peer(&self, account_mail: Option<&str>, canonicalized_mail: &str) -> Result<Peer> {
        check_mode!(self, account_mail);

        if let Some(account_mail) = account_mail {
            peer_fun!(self, "WHERE account = ?1 and address = ?2", 
                account_mail, canonicalized_mail) 
        } else {
            peer_fun!(self, "WHERE address = ?1", canonicalized_mail) 
        }
    }

    pub fn get_peer_fpr(&self, account_mail: Option<&str>, fpr: &Fingerprint) -> Result<Peer> {
        check_mode!(self, account_mail);

        if let Some(account_mail) = account_mail {
            peer_fun!(self, "WHERE account = ?1 and (key_fpr = ?2 or gossip_key_fpr = ?2)", 
                account_mail, fpr.to_hex())
        } else {
            peer_fun!(self, "WHERE key_fpr = ?1 or gossip_key_fpr = ?1", fpr.to_hex())
        }
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

    fn update_account(&self, account: &Account) -> Result<()> {
        let output = &mut Vec::new();
        account.cert.as_tsk().armored().serialize(output)?;
        let certstr = std::str::from_utf8(output)?;
        // should we insert the rev cert into the db too?
        let accountstmt = 
            "INSERT or REPLACE into account (
                address, 
                key,
                prefer,
                enable)
            values (?, ?, ?, ?);";
        // let accountstmt = 
        //     "INSERT or REPLACE into account (
        //         address, 
        //         key)
        //     values (?, ?);";
        self.con.execute(accountstmt, params![
            &account.mail, 
            &certstr,
            // todo

            &account.prefer,
            &account.enable,
        ])?;
        Ok(())
    }

    pub fn update_private_key(&self, policy: &dyn Policy, canonicalized_mail: &str) -> Result<()> {
        let now = SystemTime::now();

        // Check if we have a key, if that is the case, check if the key is ok.
        if let Ok(mut account) = self.get_account(canonicalized_mail) {
            if account.cert.primary_key().with_policy(policy, now).is_ok() {
                return Ok(())
            }
            let (cert, _) = self.gen_cert(canonicalized_mail, now)?;

            account.cert = cert;
            self.update_account(&account)
        } else {
            let (cert, _) = self.gen_cert(canonicalized_mail, now)?;
            
            let account = Account::new(canonicalized_mail, cert);
            self.update_account(&account)
        }
    }

    pub fn update_last_seen(&self, account_mail: &str,  canonicalized_mail: &str, now: &DateTime<Utc>)
        -> Result<()> {
        // We don't allow updating into the future
        // Unless we are doing testing
        if !cfg!(test) && now.cmp(&Utc::now()) == Ordering::Greater {
            return Err(anyhow::anyhow!(
                    "Date is in the future"
            ))
        }
        let seenstmt = 
            "UPDATE peer
            SET last_seen = ?1
            WHERE address = ?2
            AND account = ?3
            AND last_seen < ?1";
        self.con.execute(seenstmt, params![
            now.timestamp(),
            canonicalized_mail,
            account_mail,
        ])?;
        Ok(())
    }

    fn insert_peer(&self, peer: &Peer) -> Result<()>{
        let keystr = if let Some(ref key) = peer.cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else { None };
        let keystr_fpr = peer.cert.as_ref().map(|c| c.fingerprint().to_hex());

        let gossip_keystr = if let Some(ref key) = peer.gossip_cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else { None};
        let gossip_keystr_fpr = peer.gossip_cert.as_ref().map(|c| c.fingerprint().to_hex());

        let insertstmt = 
            "INSERT or REPLACE into peer (
                address, 
                last_seen,
                timestamp,
                key,
                key_fpr,
                gossip_timestamp,
                gossip_key,
                gossip_key_fpr,
                prefer,
                account)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        self.con.execute(insertstmt, params![
            &peer.mail, 
            &peer.last_seen.timestamp(),
            &peer.timestamp.map(|t| t.timestamp()),
            &keystr,
            &keystr_fpr,
            &peer.gossip_timestamp.map(|t| t.timestamp()),
            &gossip_keystr,
            &gossip_keystr_fpr,
            &peer.prefer,
            &peer.account,
        ])?;
        Ok(())
    }

    pub fn update_peer(&self, account_mail: &str, canonicalized_mail: &str, key: &Cert, 
        prefer: Prefer, effective_date: DateTime<Utc>, gossip: bool) -> Result<bool> {
        let peer = if self.wildcard {
            self.get_peer(None, canonicalized_mail)
        } else {
            self.get_peer(Some(account_mail), canonicalized_mail)
        };

        match peer {
            Err(_) => {
                let peer = Peer::new(canonicalized_mail, account_mail, effective_date, key, gossip, prefer);
                self.insert_peer(&peer)?;
                Ok(true)
            }
            Ok(mut peer) => {
                if effective_date.cmp(&peer.last_seen) == Ordering::Less {
                    return Ok(false)
                }

                if !gossip {
                    if peer.timestamp.is_none() || 
                        effective_date.cmp(&peer.timestamp.unwrap()) == Ordering::Greater {
                            peer.timestamp = Some(effective_date);
                            peer.cert = Some(Cow::Borrowed(key));
                            peer.account = account_mail.to_owned();
                            self.insert_peer(&peer)?;
                            return Ok(true)
                    }
                } else if peer.gossip_timestamp.is_none() ||
                        effective_date.cmp(&peer.gossip_timestamp.unwrap()) == Ordering::Greater {
                            peer.gossip_timestamp = Some(effective_date);
                            peer.gossip_cert = Some(Cow::Borrowed(key));
                            peer.account = account_mail.to_owned();
                            self.insert_peer(&peer)?;
                            return Ok(true)
                }
                self.update_last_seen(account_mail, canonicalized_mail, &effective_date)?;

                Ok(true)
            }
        }
    }
    
    pub fn recommend(&self, account_mail: Option<&str>, canonicalized_reciever: &str)
        -> UIRecommendation {
        if let Ok(peer) = self.get_peer(account_mail, canonicalized_reciever) {
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

    pub fn header(&self, canonicalized_email: &str, policy: &dyn Policy, prefer: Prefer) -> Result<AutocryptHeader> {
        let account = self.get_account(canonicalized_email)?;

        AutocryptHeader::new_sender(policy, &account.cert, canonicalized_email, prefer)
    }


    pub fn gossip_header(&self, our: Option<&str>, canonicalized_email: &str, policy: &dyn Policy) -> Result<AutocryptHeader> {

        let peer = self.get_peer(our, canonicalized_email)?;

        if let Some(ref cert) = peer.cert {
            if let Ok(mut header) = AutocryptHeader::new_sender(policy, cert, canonicalized_email, None) {
                header.header_type = AutocryptHeaderType::Gossip;
                return Ok(header)
            }
        }
        if let Some(ref cert) = peer.gossip_cert {
            if let Ok(mut header) = AutocryptHeader::new_sender(policy, cert, canonicalized_email, None) {
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

    pub fn install_message(&self, canonicalized_mail: &str, 
        mut message: AutocryptSetupMessageParser, password: &Password) -> Result<()> {
        message.decrypt(password)?;
        let decrypted = message.parse()?;
        let cert = decrypted.into_cert();

        // TODO: Check that the cert is usable

        if let Ok(mut account) = self.get_account(canonicalized_mail) {
            // We don't check which cert is newer etc.
            // We expect the user to know what he/she is doing
            account.cert = cert;
            return self.update_account(&account);
        }
        let account = Account::new(canonicalized_mail, cert);
        self.update_account(&account)
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
            let peer = if self.wildcard {
                self.get_peer(None, rep)?
            } else {
                self.get_peer(Some(canonicalized_email), rep)?
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

            let account_mail = if self.wildcard {
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

#[cfg(test)]
// [ ] Can we test just verify without without writing shitloads of code?
mod tests {
    use std::str::from_utf8;
    use chrono::{Duration, Utc};
    use crate::store::*;
    use crate::peer::*;

    use sequoia_openpgp::policy::StandardPolicy;
    use rusqlite::Connection;

    static OUR: &'static str = "art.vandelay@vandelayindustries.com";
    static PEER1: &'static str = "regina.phalange@friends.com";
    static PEER2: &'static str = "ken.adams@friends.com";

    #[derive(PartialEq)]
    enum Mode {
        Seen,
        Gossip,
        _Both, // If we want both seen and gossip (todo)
    }

    fn test_db() -> AutocryptStore {
        let con = Connection::open_in_memory().unwrap();
        setup(&con).unwrap();
        AutocryptStore { password: Some(Password::from("hunter2")), con, wildcard: false}
    }

    fn gen_peer(ctx: &AutocryptStore, account_mail: &str, canonicalized_mail: &str,
        mode: Mode, prefer: Prefer) -> Result<()> {
        let now = SystemTime::now();

        let mut builder = CertBuilder::new();
        builder = builder.add_userid(canonicalized_mail);
        builder = builder.set_creation_time(now);

        builder = builder.set_validity_period(None);

        // builder = builder.set_validity_period(
        //     Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),

        // which one to use?
        // builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        builder = builder.set_cipher_suite(CipherSuite::Cv25519);

        builder = builder.add_subkey(
            KeyFlags::empty()
            .set_transport_encryption(),
            None,
            None,
        );

        let (cert, _) = builder.generate()?;

        // Since we don't we don't we don't do as as_tsk() in insert_peer, we won't write the
        // private key
        let peer = Peer::new(canonicalized_mail, account_mail, Utc::now(), &cert, mode == Mode::Gossip, prefer);
        ctx.insert_peer(&peer).unwrap();

        Ok(())
    }

    #[test]
    fn test_gen_key() {
        let ctx = test_db();
        let policy = StandardPolicy::new();

        ctx.update_private_key(&policy, OUR).unwrap();
        let acc = ctx.get_account(OUR).unwrap();

        // check stuff in acc
        ctx.update_private_key(&policy, OUR).unwrap();
        let acc2 = ctx.get_account(OUR).unwrap();

        assert_eq!(acc, acc2);

        // check that PEER1 doesn't return anything
        if let Ok(_) = ctx.get_account(PEER1) {
            assert!(true, "PEER1 shouldn't be in the db!")
        }
    }

    #[test]
    fn test_gen_peer() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        gen_peer(&ctx, &account.mail, PEER2, Mode::Seen, Prefer::Mutual).unwrap();

        let peer1 = ctx.get_peer(Some(OUR), PEER1).unwrap();
        let peer2 = ctx.get_peer(Some(OUR), PEER2).unwrap();

        assert_eq!(peer1.mail, PEER1);
        assert_eq!(peer2.mail, PEER2);
        // Check some more properteries etc

        assert_ne!(peer1, peer2);
    }

    #[test]
    fn test_update_peer() {
        let policy = StandardPolicy::new();

        let ctx = test_db();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let now = Utc::now();

        let peer1 = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let (cert, _) = ctx.gen_cert(PEER1, now.into()).unwrap();

        ctx.update_peer(&account.mail, PEER1, &cert, Prefer::Nopreference, Utc::now(), true).unwrap();

        let updated = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        assert_ne!(peer1, updated);

        ctx.update_peer(&account.mail, PEER1, &cert, Prefer::Nopreference, Utc::now(), false).unwrap();
        let replaced = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        assert_ne!(replaced, updated)
    }

    #[test]
    fn test_update_old_peer_data() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let old_peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let past = Utc::now() - Duration::days(150);
        let (cert, _) = ctx.gen_cert(PEER1, past.into()).unwrap();

        ctx.update_peer(&account.mail, PEER1, &cert, Prefer::Nopreference, past, false).unwrap();

        let same_peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();
        assert_eq!(old_peer, same_peer);
    }

    #[test]
    fn test_update_seen() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let before = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let future = Utc::now() + Duration::days(1);
        ctx.update_last_seen(&account.mail, PEER1, &future).unwrap();

        let peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();
        assert_ne!(before.last_seen, peer.last_seen);
    }

    #[test]
    fn test_update_seen_old() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        let peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let history = Utc::now() - Duration::days(150);

        ctx.update_last_seen(&account.mail, PEER1, &history).unwrap();


        assert_ne!(history, peer.last_seen);
    }

    #[test]
    fn test_encrypt() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        ctx.update_private_key(&policy, OUR).unwrap();
        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let input = "This is a small  to test encryption";
        let mut output: Vec<u8> = vec![];
        ctx.encrypt(&policy, OUR, &[PEER1], &mut input.as_bytes(), &mut output).unwrap();
    }

    #[test]
    fn test_decrypt() {
        let ctx = test_db();
        let policy = StandardPolicy::new();

        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        let peer = Peer::new(OUR, &account.mail,Utc::now(), &account.cert, false, Prefer::Mutual);
        ctx.insert_peer(&peer).unwrap();

        let input = "This is a small  to test encryption";

        let mut middle: Vec<u8> = vec![];
        ctx.encrypt(&policy, OUR, &[OUR], &mut input.as_bytes(), &mut middle).unwrap();

        let mut output: Vec<u8> = vec![];
        let mut middle: &[u8] = &middle;

        ctx.decrypt(&policy, OUR, &mut middle, &mut output, None).unwrap();

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
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        assert_eq!(ctx.recommend(Some(OUR), PEER1), UIRecommendation::Available);
    }

    #[test]
    fn test_recommend_disable() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        assert_eq!(ctx.recommend(Some(OUR), PEER1), UIRecommendation::Disable);
        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        assert_eq!(ctx.recommend(Some(OUR), PEER2), UIRecommendation::Disable);
    }

    #[test]
    fn test_recommond_gossip() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Gossip, Prefer::Mutual).unwrap();

        assert_eq!(ctx.recommend(Some(OUR), PEER1), UIRecommendation::Discourage)
    }
}
