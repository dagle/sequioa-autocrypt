extern crate sequoia_openpgp as openpgp;
use crate::driver::SqlDriver;
use crate::store::AutocryptStore;
use crate::Result;
use openpgp::crypto::{Decryptor, Password};
use openpgp::fmt::hex;
use openpgp::packet::prelude::SecretKeyMaterial;
use openpgp::packet::{key, Key, PKESK};
use openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::policy::Policy;
use openpgp::types::{PublicKeyAlgorithm, SymmetricAlgorithm};
use openpgp::{crypto, Cert, Fingerprint, KeyID, Packet};
use std::collections::HashMap;

// We pair a session key with the algorithm for easier access.
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

/// Since the key can be locked or unlocked we use this abstraction
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

    fn unlock(&mut self, p: &Option<Password>) -> Result<Box<dyn Decryptor>> {
        if let Some(p) = p {
            let algo = self.key.pk_algo();
            self.key.secret_mut().decrypt_in_place(algo, p)?;
            let keypair = self.key.clone().into_keypair()?;
            return Ok(Box::new(keypair));
        }
        Err(anyhow::anyhow!("Key is encrypted but no password supplied"))
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

pub(crate) fn remove_password(cert: Cert, password: &Password) -> Result<Cert> {
    let mut decrypted: Vec<Packet> = vec![decrypt_key(
        cert.primary_key().key().clone().parts_into_secret()?,
        password,
    )?
    .into()];

    for ka in cert.keys().subkeys().secret() {
        decrypted.push(decrypt_key(ka.key().clone().parts_into_secret()?, password)?.into());
    }

    cert.insert_packets(decrypted)
}

pub(crate) fn set_password(cert: Cert, password: &Password) -> Result<Cert> {
    let mut encrypted: Vec<Packet> = vec![cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .encrypt_secret(password)?
        .into()];
    for ka in cert.keys().subkeys().unencrypted_secret() {
        encrypted.push(
            ka.key()
                .clone()
                .parts_into_secret()?
                .encrypt_secret(password)?
                .into(),
        );
    }
    cert.insert_packets(encrypted)
}

pub fn decrypt_key<R>(
    key: Key<key::SecretParts, R>,
    password: &Password,
) -> Result<Key<key::SecretParts, R>>
where
    R: key::KeyRole + Clone,
{
    let key = key.parts_as_secret()?;
    match key.secret() {
        SecretKeyMaterial::Unencrypted(_) => Ok(key.clone()),
        SecretKeyMaterial::Encrypted(_) => {
            if let Ok(key) = key.clone().decrypt_secret(password) {
                return Ok(key);
            }
            Err(anyhow::anyhow!("Password isn't correct"))
        }
    }
}

pub struct VHelper<'a, T: SqlDriver> {
    ctx: &'a AutocryptStore<T>,
    account_email: Option<&'a str>,
}

impl<'a, T: SqlDriver> VHelper<'a, T> {
    pub fn new(ctx: &'a AutocryptStore<T>, account_email: Option<&'a str>) -> Self {
        VHelper { ctx, account_email }
    }
}

impl<'a, T: SqlDriver> VerificationHelper for VHelper<'a, T> {
    /// Get keys from the db, we get both keys and gossip_keys
    /// matching the fingerprint and keyid
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = Vec::new();
        for id in _ids {
            if let Ok(peer) = self.ctx.conn.get_peer(self.account_email, id.into()) {
                if let Some(c) = peer.cert {
                    certs.push(c.into_owned())
                }
                if let Some(c) = peer.gossip_cert {
                    certs.push(c.into_owned())
                }
            }
        }
        Ok(certs)
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        // TODO: Save the result
        Ok(())
    }
}

pub struct DHelper<'a, T: SqlDriver> {
    ctx: &'a AutocryptStore<T>,
    sk: Option<SessionKey>,
    keys: HashMap<KeyID, PrivateKey>,
    fp: Fingerprint,

    helper: VHelper<'a, T>,
}

impl<'a, T: SqlDriver> DHelper<'a, T> {
    pub fn new(
        ctx: &'a AutocryptStore<T>,
        policy: &dyn Policy,
        account_mail: Option<&'a str>,
        cert: Cert,
        sk: Option<SessionKey>,
    ) -> Self {
        let mut keys: HashMap<KeyID, PrivateKey> = HashMap::new();

        for key in cert
            .keys()
            .with_policy(policy, None)
            .supported()
            .for_transport_encryption()
        {
            if let Ok(key) = key.parts_as_secret() {
                let id: KeyID = key.key().keyid();
                keys.insert(id, PrivateKey::new(key.key().clone()));
            }
        }
        DHelper {
            ctx,
            sk,
            keys,
            fp: cert.fingerprint(),
            helper: VHelper::new(ctx, account_mail),
        }
    }
}
impl<'a, T: SqlDriver> VerificationHelper for DHelper<'a, T> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        // TODO: Being able to turn off verification

        self.helper.get_certs(ids)
    }
    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        // TODO: Save the result
        Ok(())
    }
}

impl<'a, T: SqlDriver> DHelper<'a, T> {
    fn try_decrypt<D>(
        &self,
        pkesk: &PKESK,
        sym_algo: Option<SymmetricAlgorithm>,
        _pk_algo: PublicKeyAlgorithm,
        mut keypair: Box<dyn crypto::Decryptor>,
        decrypt: &mut D,
    ) -> bool
    where
        D: FnMut(SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool,
    {
        pkesk
            .decrypt(&mut *keypair, sym_algo)
            .and_then(
                |(algo, sk)| {
                    if decrypt(algo, &sk) {
                        Some(sk)
                    } else {
                        None
                    }
                },
            )
            .is_some()
        // TODO: match on the result and save something
    }
}

impl<'a, T: SqlDriver> DecryptionHelper for DHelper<'a, T> {
    // We don't use the skesks because we know that the key should be
    // a pkesk with autoencrypt, since it only allows those kind of encryptions.
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool,
    {
        // Maybe do sk, if it speed things up?
        if let Some(sk) = &self.sk {
            let decrypted = if let Some(sa) = sk.symmetric_algo {
                let res = decrypt(sa, &sk.session_key);
                if res {
                    // TODO: we want to save some form of result
                }
                res
            } else {
                // We don't know which algorithm to use,
                // try to find one that decrypts the .
                let mut ret = false;

                for i in 1u8..=19 {
                    let sa = SymmetricAlgorithm::from(i);
                    if decrypt(sa, &sk.session_key) {
                        // TODO: we want to save some form of result

                        // self.result.set_cipher(cypher_to_cypher(sa));
                        ret = true;
                        break;
                    }
                }
                ret
            };
            if decrypted {
                // TODO: we want to save some form of result

                // if (self.flags & gmime::DecryptFlags::EXPORT_SESSION_KEY).bits() > 0 {
                //     self.result.set_session_key(Some(&hex::encode(&sk.session_key)));
                // }
                return Ok(None);
            }
        }

        // should we support unencrypted keys?
        // leave it for now
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.keys.get_mut(keyid) {
                let algo = key.pk_algo();
                if let Some(d) = key.get_unlock() {
                    if self.try_decrypt(pkesk, sym_algo, algo, d, &mut decrypt) {
                        return Ok(Some(self.fp.clone()));
                    }
                }
            }
        }

        for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if !pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient();
            if let Some(key) = self.keys.get_mut(keyid) {
                if key.get_unlock().is_some() {
                    continue;
                }
                if let Ok(decryptor) = key.unlock(&self.ctx.password) {
                    let algo = key.pk_algo();
                    if self.try_decrypt(pkesk, sym_algo, algo, decryptor, &mut decrypt) {
                        return Ok(Some(self.fp.clone()));
                    }
                } else {
                    return Err(anyhow::anyhow!("Password is wrong for our key"));
                }
            }
        }
        Err(anyhow::anyhow!("Couldn't decrypt "))
    }
}
