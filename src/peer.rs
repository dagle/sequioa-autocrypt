extern crate sequoia_openpgp as openpgp;
use std::borrow::Cow;

use chrono::{DateTime, Utc};
use openpgp::{Cert, policy::Policy, serialize::stream::Recipient};
use crate::Result;

// we try to to get an encryption key for the specific field
// and return the key if we find one
macro_rules! encrypt_key {
    ($select:expr, $policy:expr) => {
        if let Some(ref cert) = $select {
            if let Some(key) = cert.keys().with_policy($policy, None).alive().revoked(false)
                .supported().for_transport_encryption().map(|ka| ka.key()).nth(0) {
                return Ok(key.into())
            }
        }
    }
}

/// Do we and/or peers prefer encrypted emails or cleartext emails.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Prefer {
    Mutual,
    Nopreference,
    // Noencrypt,
    // don't encrypt?
}

impl Default for Prefer {
    fn default() -> Self {
        Prefer::Nopreference
    }
}

impl From<Prefer> for Option<&str> {
    fn from(value: Prefer) -> Self {
        match value {
            Prefer::Mutual => Some("mutual"),
            Prefer::Nopreference => Some("nopreference"),
            // We don't want to output anything if we don't want to encypt
            // Prefer::Noencrypt => None,
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct Peer<'a> {
    pub mail: String,
    pub account: String,
    pub last_seen: DateTime<Utc>,
    pub timestamp: Option<DateTime<Utc>>,
    pub cert: Option<Cow<'a, Cert>>,
    pub gossip_timestamp: Option<DateTime<Utc>>,
    pub gossip_cert: Option<Cow<'a, Cert>>,
    pub prefer: Prefer,
}

impl<'a> Peer<'a> {
    pub fn new(mail: &str, account: &str, now: DateTime<Utc>, key: &'a Cert, gossip: bool, prefer: Prefer) -> Self{
        if !gossip {
            Peer {
                mail: mail.to_owned(),
                account: account.to_owned(),
                last_seen: now,
                timestamp: Some(now),
                cert: Some(Cow::Borrowed(key)),
                gossip_timestamp: None,
                gossip_cert: None,
                prefer,
            }
        } else {
            Peer {
                mail: mail.to_owned(),
                account: account.to_owned(),
                last_seen: now,
                timestamp: None,
                cert: None,
                gossip_timestamp: Some(now),
                gossip_cert: Some(Cow::Borrowed(key)),
                prefer,
            }
        }
    }
    pub fn get_recipient(&'a self, policy: &'a dyn Policy) -> Result<Recipient> {
        encrypt_key!(self.cert, policy);
        encrypt_key!(self.gossip_cert, policy);
        return Err(anyhow::anyhow!(
                "Couldn't find any key for transport encryption for peer"));
    }
}
