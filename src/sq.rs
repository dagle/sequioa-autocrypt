use std::{collections::{HashMap, hash_map::Entry, HashSet}, fs::{File, self}, io::{self, Read, Write}, time::SystemTime, str::FromStr, borrow::Borrow};
 
extern crate sequoia_openpgp as openpgp;
use gmime::{traits::{SignatureListExt, SignatureExt, CertificateExt, DecryptResultExt, CertificateListExt}, PubKeyAlgo, DigestAlgo, DecryptFlags, EncryptFlags};
use openpgp::{Fingerprint, types::{SignatureType, PublicKeyAlgorithm, HashAlgorithm, KeyFlags, CompressionAlgorithm, SymmetricAlgorithm}, parse::stream::{VerifierBuilder, VerificationHelper, MessageStructure, MessageLayer, DetachedVerifierBuilder, VerificationResult, DecryptorBuilder, DecryptionHelper}, KeyID, cert::{prelude::ValidErasedKeyAmalgamation, amalgamation::{ValidAmalgamation, key::PrimaryKey}}, crypto::{self, Password, Decryptor}, fmt::hex};
use openpgp::serialize::stream::*;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;
use openpgp::serialize::stream::Message;
use openpgp::serialize::Serialize;
use anyhow::Context;
extern crate chrono;
use chrono::offset::Utc;
use chrono::DateTime;

use openpgp::cert::{
        Cert,
        CertParser,
    };

use openpgp::parse::Parse;

use super::{imp::SqContext, query::Query};

// Exports certs based on key-ids
// Maybe this should take a policy?
pub fn export_keys(ctx: &SqContext, patterns: &[&str], 
    output: &mut (dyn io::Write + Send + Sync))
    -> openpgp::Result<i32> {
    let queries: Vec<Query> = patterns.iter().map(|pat| Query::from(*pat)).collect();

    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();

    let mut num = 0;
    for cert in certs {
        if queries.iter().any(|q| q.matches(&cert)) {
            cert.armored().export(output)?;
            num += 1;
        }
    }
    Ok(num)
}

// Import certs into the db and try to merge them with existing ones
pub fn import_keys(ctx: &SqContext, input: &mut (dyn io::Read + Send + Sync))
    -> openpgp::Result<i32> {

    let path = ctx.keyring.borrow();
    let keyring = fs::OpenOptions::new()
        .read(true)
        .open(&*path)?;

    let mut certs: HashMap<Fingerprint, Option<Cert>> = HashMap::new();

    for cert in CertParser::from_reader(&keyring)? {
        let cert = cert.context(
            "Malformed certificate in the keyring".to_string())?;
        match certs.entry(cert.fingerprint()) {
            e @ Entry::Vacant(_) => {
                e.or_insert(Some(cert));
            },
            Entry::Occupied(mut e) => {
                let e = e.get_mut();
                let curr = e.take().unwrap();
                let _ = curr.merge_public(cert)
                    .map(|c| { 
                        *e = Some(c);
                    });
            }
        }
    }
    drop(keyring);

    let mut num = 0;
    for cert in CertParser::from_reader(input)? {
        let cert = cert.context(
            "Trying to import Malformed certificate into keyring".to_string())?;
        match certs.entry(cert.fingerprint()) {
            e @ Entry::Vacant(_) => {
                e.or_insert(Some(cert));
                num += 1;
            }
            Entry::Occupied(mut e) => {
                let e = e.get_mut();
                let curr = e.take().unwrap();
                let c = curr.merge_public(cert)?;
                *e = Some(c);
                // What if e and cert are equal
                // should we add num += 1? What is the sementics 
                num += 1;
            }
        }
    }

    let mut output = File::create(&*path)?;

    for fpr in certs.keys() {
        if let Some(Some(cert)) = certs.get(fpr) {
            Serialize::serialize(&cert.as_tsk().armored(), &mut output)?;
        }
    }
    Ok(num)
}

fn get_signing_key<C>(sq: &SqContext, certs: &[C], p: &dyn Policy,
               pattern: &str,
               timestamp: Option<SystemTime>)
    -> openpgp::Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: Borrow<Cert> {

    let query = Query::from(pattern);
    
    let mut kas = query.get_signing_keys(certs, p, timestamp);

    kas.sort_by_key(|ka| 
        (ka.alive().is_ok(),
        ka.creation_time(),
        ka.primary(),
        ka.pk_algo(), ka.fingerprint()
         ));

    if let Some(ka) = kas.iter().nth(0) {
    // for ka in kas {
        let key = ka.key().clone();
        // signing keys should always contain secret?
        if let Some(secret) = key.optional_secret() {
            match secret {
                SecretKeyMaterial::Encrypted(ref e) => {
                    let cert = ka.cert();
                    let (userid, hint) = match cert.primary_userid().ok() {
                        Some(uid) => { 
                            let datetime: DateTime<Utc> = key.creation_time().into();
                            (uid.userid().name().ok().flatten(), format!(concat!(
                                "Please enter the passphare to unlock the",
                                "secret for OpenPGP certificate:\n",
                                "{}\n",
                                "{} {}\n",
                                "created {} {}"),
                                uid.userid(),
                                key.pk_algo(),
                                key.keyid(),
                                datetime.format("%Y-%m-%d"),
                                KeyID::from(cert.fingerprint())))
                        },
                        None => (None, format!(concat!("Please enter the passphare to unlock the",
                                "secret for OpenPGP certificate:\n {}"), KeyID::from(cert.fingerprint()))),
                    };
                    for i in 0..3 {
                        let passwd = sq.ask_password(userid.as_deref(), &hint, i > 0)?;
                        let result = e.decrypt(key.pk_algo(), &passwd.into());
                        if let Ok(res) = result {
                            return Ok(Box::new(crypto::KeyPair::new(key, res).unwrap()))
                        }
                    }
                    return Err(anyhow::anyhow!("Failed to decrypt key"))
                }
                SecretKeyMaterial::Unencrypted(ref u) => {
                    return Ok(Box::new(crypto::KeyPair::new(key.clone(), u.clone()).unwrap()))
                }
            };
        }
    }
    Err(anyhow::anyhow!("Couldn't find any key for signing"))
}

pub fn sign(ctx: &SqContext, policy: &dyn Policy, detach: bool,
        input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync), userid: &str)
    -> openpgp::Result<i32> {

    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
    let tsk = get_signing_key(ctx, &certs, policy, userid, None)?;

    if detach {
        sign_detach(input, output, tsk)
    } else {
        clearsign(input, output, tsk)
    }
}


fn clearsign(input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync), keypair: Box<dyn crypto::Signer + Send + Sync>)
    -> openpgp::Result<i32>
{

    let message = Message::new(output);

    let signer = Signer::with_template(
        message, keypair,
        signature::SignatureBuilder::new(SignatureType::Text))
        .cleartext();

    let mut message = signer.build()?;
    io::copy(input, &mut message)?;

    message.finalize()?;
 
    Ok(10)
}

fn sign_detach(input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync), keypair: Box<dyn crypto::Signer + Send + Sync>)
    -> openpgp::Result<i32>
{

    let message = Message::new(output);

    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Signature)
        .build()?;

    let mut message = Signer::with_template(
        message, keypair,
        signature::SignatureBuilder::new(SignatureType::Binary))
        .detached().build()?;

    io::copy(input, &mut message)?;

    message.finalize()?;
 
    Ok(10)
}

struct VHelper<'a> {
    ctx: &'a SqContext,
    
    trusted: HashSet<KeyID>,
    list: gmime::SignatureList,
}

pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

macro_rules! cert_set {
    ($cert:ident.$var:ident, $value:expr) => {
        match $value {
            Ok(Some(v)) => $cert.$var(&v),
            _ => {}
        }
    };
}

#[allow(deprecated)]
fn algo_to_algo(algo: PublicKeyAlgorithm) -> PubKeyAlgo {
    match algo {
        PublicKeyAlgorithm::RSAEncryptSign => gmime::PubKeyAlgo::RsaE,
        PublicKeyAlgorithm::RSAEncrypt => gmime::PubKeyAlgo::RsaE,
        PublicKeyAlgorithm::RSASign => gmime::PubKeyAlgo::RsaS,
        PublicKeyAlgorithm::ElGamalEncrypt => gmime::PubKeyAlgo::ElgE,
        PublicKeyAlgorithm::DSA => gmime::PubKeyAlgo::Dsa,
        PublicKeyAlgorithm::ECDH => gmime::PubKeyAlgo::Ecdh,
        PublicKeyAlgorithm::ECDSA => gmime::PubKeyAlgo::Ecdsa,
        PublicKeyAlgorithm::ElGamalEncryptSign => gmime::PubKeyAlgo::ElgE,
        PublicKeyAlgorithm::EdDSA => gmime::PubKeyAlgo::RsaE,
        PublicKeyAlgorithm::Private(v) => gmime::PubKeyAlgo::__Unknown(v as i32),
        PublicKeyAlgorithm::Unknown(v) => gmime::PubKeyAlgo::__Unknown(v as i32),
        _ => todo!(),
    }
}

fn cypher_to_cypher(algo: SymmetricAlgorithm) -> gmime::CipherAlgo {
    match algo {
        // this shouldn't happen?
        SymmetricAlgorithm::Unencrypted => todo!(),
        SymmetricAlgorithm::IDEA => gmime::CipherAlgo::Idea,
        SymmetricAlgorithm::TripleDES => gmime::CipherAlgo::_3des,
        SymmetricAlgorithm::CAST5 => gmime::CipherAlgo::Cast5,
        SymmetricAlgorithm::Blowfish => gmime::CipherAlgo::Blowfish,
        SymmetricAlgorithm::AES128 => gmime::CipherAlgo::Aes,
        SymmetricAlgorithm::AES192 => gmime::CipherAlgo::Aes192,
        SymmetricAlgorithm::AES256 => gmime::CipherAlgo::Aes256,
        SymmetricAlgorithm::Twofish => gmime::CipherAlgo::Twofish,
        SymmetricAlgorithm::Camellia128 => gmime::CipherAlgo::Camellia128,
        SymmetricAlgorithm::Camellia192 => gmime::CipherAlgo::Camellia192,
        SymmetricAlgorithm::Camellia256 => gmime::CipherAlgo::Camellia256,
        SymmetricAlgorithm::Private(_) => todo!(),
        SymmetricAlgorithm::Unknown(_) => todo!(),
        _ => todo!(),
    }
}

fn hash_to_hash(algo: HashAlgorithm) -> DigestAlgo {
    match algo {
        HashAlgorithm::MD5 => gmime::DigestAlgo::Md5,
        HashAlgorithm::SHA1 => gmime::DigestAlgo::Sha1,
        HashAlgorithm::RipeMD => gmime::DigestAlgo::Ripemd160,
        HashAlgorithm::SHA256 => gmime::DigestAlgo::Sha256,
        HashAlgorithm::SHA384 => gmime::DigestAlgo::Sha384,
        HashAlgorithm::SHA512 => gmime::DigestAlgo::Sha512,
        HashAlgorithm::SHA224 => gmime::DigestAlgo::Sha224,
        HashAlgorithm::Private(v) => gmime::DigestAlgo::__Unknown(v as i32),
        HashAlgorithm::Unknown(v) => gmime::DigestAlgo::__Unknown(v as i32),
        _ => todo!(),
    }
}

macro_rules! unix_time {
    ($cert:ident.$var:ident, $value:expr) => {
        match $value {
            Some(v) => {
                match v.duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(v) => $cert.$var(v.as_secs() as i64),
                    _ => {}
                }
            }
            _ => {}
        }
    };
}

impl<'a> VHelper<'a> {
    fn new(ctx: &'a SqContext)
           -> Self {
        let list = gmime::SignatureList::new();
        VHelper {
            ctx,
            trusted: HashSet::new(),
            list,
        }
    }

    fn make_signature(&self, sig: &Signature, status: gmime::SignatureStatus,
        ka: Option<&ValidErasedKeyAmalgamation<'a, key::PublicParts>>,
        cert: Option<&'a Cert>)
        -> gmime::Signature {
            let gsig = gmime::Signature::new();

            gsig.set_status(status);
            unix_time!(gsig.set_expires, sig.signature_expiration_time());
            unix_time!(gsig.set_created, sig.signature_creation_time());

            let gcert = gmime::Certificate::new();
            gcert.set_pubkey_algo(algo_to_algo(sig.pk_algo()));
            gcert.set_digest_algo(hash_to_hash(sig.hash_algo()));
            let finger = sig.issuer_fingerprints().next();
            if let Some(finger) = finger {
                let finger = finger.to_hex();
                gcert.set_fingerprint(&finger);
            }

            if let Some(key) = ka {
                let issuer = key.key().keyid();
                let level = sig.level();

                let trusted = self.trusted.contains(&issuer);

                // TODO: Are these trust leveles mapped correctly?
                let trust = match (trusted, level) {
                    (true, 0) => gmime::Trust::Full,
                    (true, 1) => gmime::Trust::Marginal,
                    (false, _) => gmime::Trust::Unknown,
                    (_, _) => gmime::Trust::Unknown,
                };

                gcert.set_trust(trust);

                let cert = key.cert();

                // Is this right, don't we want the userid connect to 
                // to the signature?
                if let Ok(id) = cert.primary_userid() {
                    // Not setting these, sincenot relevant
                    // validity, issuer_name, set_issuer_serial,

                    cert_set!(gcert.set_name, id.name());
                    cert_set!(gcert.set_email, id.email());

                    let userid = String::from_utf8_lossy(id.userid().value());

                    gcert.set_user_id(&userid);

                }

                // TODO:
                // if we find subkeys, just set the date of the subkeys instead?
                // cert.set_created();
                // cert.set_expires();

            } else if let Some(_cert) = cert {
                gcert.set_trust(gmime::Trust::Never)
            }
            gsig.set_certificate(&gcert);

            gsig
    }

    fn make_siglist(&mut self, result: &[VerificationResult])
        -> Result<()> {
        for (idx, res) in result.iter().enumerate() {
            match res {
                Ok(ref res) => {
                    let sig = self.make_signature(res.sig, gmime::SignatureStatus::Green, Some(&res.ka), None);
                    self.list.insert(idx as i32, &sig);
                }
                Err(ref err) => {
                    match err {
                        openpgp::parse::stream::VerificationError::MalformedSignature { sig, error: _ } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::SysError, None, None);
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::MissingKey { sig } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::KeyMissing, None, None);
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::UnboundKey { sig, cert, error: _ } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::Red, None, Some(cert));
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::BadKey { sig, ka, error: _ } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::Red, 
                                Some(ka), None);
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::BadSignature { sig, ka, error: _ } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::Red,
                                Some(ka), None);
                            self.list.add(&sig);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let path = self.ctx.keyring.borrow();
        let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
        let seen: HashSet<_> = certs.iter()
            .flat_map(|cert| {
                cert.keys().map(|ka| ka.key().fingerprint().into())
            }).collect();
        // Explicitly provided keys are trusted.
        self.trusted = seen;

        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::SignatureGroup { ref results } => {
                    self.make_siglist(results)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

pub fn verify(ctx: &SqContext, policy: &dyn Policy, _flags: gmime::VerifyFlags, input: &mut (dyn io::Read + Send + Sync),
    sigstream: Option<&mut (dyn io::Read + Send + Sync)>, output: Option<&mut (dyn io::Write + Send + Sync)>) -> openpgp::Result<Option<gmime::SignatureList>> {

    let helper = VHelper::new(ctx);
    let helper = if let Some(dsig) = sigstream {
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
            return Err(anyhow::anyhow!("None detach message but no output stream"))
        }
    };

    Ok(Some(helper.list))
}

struct PrivateKey {
    key: Key<key::SecretParts, key::UnspecifiedRole>,
}

impl PrivateKey {
    fn new(key: Key<key::SecretParts, key::UnspecifiedRole>) -> Self {
        Self { key } 
    }

    fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.key.pk_algo()
    }

    fn unlock(&mut self, p: &Password) -> openpgp::Result<Box<dyn Decryptor>> {
        let algo = self.key.pk_algo();
        self.key.secret_mut().decrypt_in_place(algo, p)?;
        let keypair = self.key.clone().into_keypair()?;
        Ok(Box::new(keypair))
    }

    fn get_unlock(&self) -> Option<Box<dyn Decryptor>> {
        if self.key.secret().is_encrypted() {
            None
        } else {
            // `into_keypair` fails if the key is encrypted but we
            // have already checked for that
            let keypair = self.key.clone().into_keypair().unwrap();
            Some(Box::new(keypair))
        }
    }
}

struct DHelper<'a> {
    ctx: &'a SqContext,
    sk: Option<SessionKey>,
    flags: DecryptFlags,

    helper: VHelper<'a>,

    key_identities: HashMap<KeyID, Fingerprint>,
    keys: HashMap<KeyID, PrivateKey>,
    key_hints: HashMap<KeyID, String>,
    user_id: HashMap<KeyID, String>,
    
    result: gmime::DecryptResult,
}

impl<'a> DHelper<'a> {
    fn new(ctx: &'a SqContext, policy: &dyn Policy, flags: DecryptFlags, secrets: Vec<Cert>, sk: Option<SessionKey>)
           -> Self {
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        let mut hints: HashMap<KeyID, String> = HashMap::new();
        let mut keys: HashMap<KeyID, PrivateKey> = HashMap::new();
        let mut user_id: HashMap<KeyID, String> = HashMap::new();

        let result = gmime::DecryptResult::new();

        for cert in secrets {
            for key in cert.keys()
                .with_policy(policy, None)
                .supported()
                .for_transport_encryption().for_storage_encryption()
            {

                let (userid, hint) = match cert.with_policy(policy, None)
                    .and_then(|valid_cert| valid_cert.primary_userid()).ok()
                    {
                        // Maybe we can do this better in the future
                        Some(uid) => { 
                            let datetime: DateTime<Utc> = key.creation_time().into();
                            (uid.userid().name().ok().flatten(), format!(concat!(
                                "Please enter the passphare to unlock the",
                                "secret for OpenPGP certificate:\n",
                                "{}\n",
                                "{} {}\n",
                                "created {} {}"),
                                uid.userid(),
                                key.pk_algo(),
                                key.keyid(),
                                datetime.format("%Y-%m-%d"),
                                KeyID::from(cert.fingerprint())))
                        },
                        None => (None, format!(concat!("Please enter the passphare to unlock the,
                                secret for OpenPGP certificate:\n {}"), KeyID::from(cert.fingerprint()))),
                    };
                if let Ok(key) = key.parts_as_secret() {
                    let id: KeyID = key.key().keyid();
                    identities.insert(id.clone(), cert.fingerprint());
                    keys.insert(id.clone(), PrivateKey::new(key.key().clone()));
                    if let Some(userid) = userid {
                        user_id.insert(id.clone(), userid);
                    }
                    hints.insert(id, hint);
                }
            }
        }

        DHelper {
            ctx,
            sk,
            flags,

            helper: VHelper::new(ctx),

            keys,
            key_hints: hints,
            key_identities: identities,
            user_id,

            result,
        }
    }

    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      sym_algo: Option<SymmetricAlgorithm>,
                      pk_algo: PublicKeyAlgorithm,
                      mut keypair: Box<dyn crypto::Decryptor>,
                      decrypt: &mut D)
                      -> Option<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool
    {
        let keyid: KeyID = keypair.public().fingerprint().into();
        match pkesk.decrypt(&mut *keypair, sym_algo)
            .and_then(|(algo, sk)| {
                if decrypt(algo, &sk) { Some(sk) } else { None }
            })
        {
            Some(sk) => {
                if (self.flags & gmime::DecryptFlags::EXPORT_SESSION_KEY).bits() > 0 {
                    self.result.set_session_key(Some(&hex::encode(sk)));
                }

                let certresult_list = gmime::CertificateList::new();
                self.result.set_recipients(&certresult_list);

                let cert = gmime::Certificate::new();
                certresult_list.add(&cert);

                cert.set_key_id(&keyid.to_hex());
                cert.set_pubkey_algo(algo_to_algo(pk_algo));

                Some(self.key_identities.get(&keyid).cloned())
            },
            None => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionKey {
    pub session_key: openpgp::crypto::SessionKey,
    pub symmetric_algo: Option<SymmetricAlgorithm>,
}

impl std::str::FromStr for SessionKey {
    type Err = anyhow::Error;

    /// Parse a session key. The format is: an optional prefix specifying the
    /// symmetric algorithm as a number, followed by a colon, followed by the
    /// session key in hexadecimal representation.
    fn from_str(sk: &str) -> anyhow::Result<Self> {
        let result = if let Some((algo, sk)) = sk.split_once(':') {
            let algo = SymmetricAlgorithm::from(algo.parse::<u8>()?);
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: Some(algo),
            }
        } else {
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: None,
            }
        };
        Ok(result)
    }
}

impl<'a> VerificationHelper for DHelper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        if self.flags != DecryptFlags::NO_VERIFY {
            return self.helper.get_certs(ids)
        }
        Ok(vec![])
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        if self.flags != DecryptFlags::NO_VERIFY {
            for layer in structure {
                match layer {
                    MessageLayer::SignatureGroup { ref results } => {
                        self.helper.make_siglist(results)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

impl<'a> DecryptionHelper for DHelper<'a> {
    fn decrypt<D>(&mut self,
        pkesks: &[openpgp::packet::PKESK],
        skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D)
        -> openpgp::Result<Option<openpgp::Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool
    {

        if let Some(sk) = &self.sk {
            let decrypted = if let Some(sa) = sk.symmetric_algo {
                let res = decrypt(sa, &sk.session_key);
                if res {
                    self.result.set_cipher(cypher_to_cypher(sa));
                }
                res
            } else {
                // We don't know which algorithm to use,
                // try to find one that decrypts the message.
                let mut ret = false;

                for i in 1u8..=19 {
                    let sa = SymmetricAlgorithm::from(i);
                    if decrypt(sa, &sk.session_key) {
                        self.result.set_cipher(cypher_to_cypher(sa));
                        ret = true;
                        break;
                    }
                }
                ret
            };
            if decrypted {
                if (self.flags & gmime::DecryptFlags::EXPORT_SESSION_KEY).bits() > 0 {
                    self.result.set_session_key(Some(&hex::encode(&sk.session_key)));
                }
                return Ok(None);
            }
        }

        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.keys.get_mut(keyid) {
                let algo = key.pk_algo();
                if let Some(fp) = key.get_unlock()
                    .and_then(|k| 
                        self.try_decrypt(pkesk, sym_algo, algo, k, &mut decrypt))
                    {
                        return Ok(fp)
                    }
            }
        }


        'next_key: for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient();
            if let Some(key) = self.keys.get_mut(keyid) {
                if key.get_unlock().is_some() {
                    continue;
                }
                let prompt = self.key_hints.get(keyid).unwrap();
                let userid = self.user_id.get(keyid);

                for i in 0..3 {

                    let passwd = self.ctx.ask_password(userid.map(|x| x.as_str()), prompt, i > 0)?.into();

                    if let Ok(decryptor) = key.unlock(&passwd) {
                        if let Some(fp) = {
                            let algo = key.pk_algo();
                            self.try_decrypt(pkesk, sym_algo, algo, decryptor,
                                &mut decrypt)
                        }
                        {
                            return Ok(fp);
                        }
                        continue 'next_key;
                    }
                }
            }
        }

        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            for key in self.keys.values() {
                if let Some(fp) = key.get_unlock()
                    .and_then(|k|
                        self.try_decrypt(pkesk, sym_algo, key.pk_algo(), k, &mut decrypt))
                {
                    return Ok(fp);
                }
            }
        }

        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            // To appease the borrow checker, iterate over the
            // hashmap, awkwardly.
            'next_multi: for keyid in self.keys.keys().cloned().collect::<Vec<_>>()
            {
                let key = self.keys.get_mut(&keyid).unwrap();
                if key.get_unlock().is_some() {
                    continue;
                }
                let prompt = self.key_hints.get(&keyid).unwrap();
                let userid = self.user_id.get(&keyid);

                for i in 0..3 {

                    let passwd = self.ctx.ask_password(userid.map(|x| x.as_str()),
                        prompt, i > 0)?.into();

                    if let Ok(decryptor) = key.unlock(&passwd) {
                        if let Some(fp) = {
                            let algo = key.pk_algo();
                            self.try_decrypt(pkesk, sym_algo, algo, decryptor,
                                &mut decrypt)
                        }
                        {
                            return Ok(fp);
                        }
                        continue 'next_multi;
                    }
                }
            }
        }

        for i in 0..3 {
            let prompt = "Please enter the passphare to decrypt the message";
            let passwd = self.ctx.ask_password(None, prompt, i > 0)?.into();

            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&passwd).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    if (self.flags & gmime::DecryptFlags::EXPORT_SESSION_KEY).bits() > 0 {
                        self.result.set_session_key(Some(&hex::encode(sk)));
                    }
                    return Ok(None)
                }
            }
        }
        Err(anyhow::anyhow!("Couldn't decrypt message"))
    }
}

pub fn decrypt(ctx: &SqContext, policy: &dyn Policy, flags: DecryptFlags,
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync),
    sk: Option<&str>)
        -> openpgp::Result<gmime::DecryptResult> {

    let sk = sk.and_then(|x| SessionKey::from_str(x).ok());
    let path = ctx.keyring.borrow();
    let secrets: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
    let helper = DHelper::new(ctx, policy, flags, secrets, sk);
    let mut decryptor = DecryptorBuilder::from_reader(input)?
        .with_policy(policy, None, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output)?;

    let helper = decryptor.into_helper();
    helper.result.set_signatures(&helper.helper.list);
    Ok(helper.result)
}

// TODO: Fix flags when the new gir is done
// Then EncryptFlags should be a bitfield
pub fn encrypt(ctx: &SqContext, policy: &dyn Policy, flags: EncryptFlags,
    sign: bool, userid: Option<&str>, recipients: &[&str],
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync))
        -> Result<i32> {

    if recipients.is_empty() {
        return Err(anyhow::anyhow!(
            "No recipient"));
    }
    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();

    let mut message = Message::new(output);

    if flags == EncryptFlags::Symmetric {
        let prompt = "Please enter a password for symmetric encryption";
        let passwd = ctx.ask_password(None, prompt, false)?;

        let armor = Armorer::new(message).build()?;

        let encryptor = Encryptor::with_passwords(armor, Some(passwd))
            .symmetric_algo(SymmetricAlgorithm::AES128);

        message = encryptor.build()
            .context("Failed to create symmetric encryptor")?;
    }

    let mode = KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption();

    let queries: Vec<Query> = recipients.iter().map(|pat| Query::from(*pat)).collect();
    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    let mut signing_keys: Vec<&Cert> = Vec::new();


    for q in queries {
        if let Some(cert) = q.get_cert(&certs) {
            signing_keys.push(cert);
            for key in cert.keys().with_policy(policy, None).alive().revoked(false)
                .key_flags(&mode).supported().map(|ka| ka.key()) {
                    recipient_subkeys.push(key.into());
            }
        } else {
            return Err(anyhow::anyhow!(
                    "Can't find all recipients"));
        }
    }

    let message = Armorer::new(message).build()?;
    let encryptor = Encryptor::for_recipients(message, recipient_subkeys);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    if flags == EncryptFlags::NoCompress {
        sink = Compressor::new(sink).algo(CompressionAlgorithm::Uncompressed).build()?;
    }

    if sign {
        if let Some(userid) = userid {
            let tsk = get_signing_key(ctx, &certs, policy, userid, None)
                .context("Couldn't find signing cert for: {}")?;
            let mut signer = Signer::new(sink, tsk);
            for r in signing_keys.iter() {
                signer = signer.add_intended_recipient(r);
            }
            sink = signer.build()?;
        } else {
            return Err(anyhow::anyhow!("Signing enabled but no userid"));
        }
    }
    // if not signing, we should still add recipients?

    let mut message = LiteralWriter::new(sink).build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut message)
        .context("Failed to encrypt")?;

    message.finalize()
        .context("Failed to encrypt")?;

    Ok(0)
}
