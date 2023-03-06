extern crate sequoia_openpgp as openpgp;
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

#[derive(PartialEq, Debug)]
pub struct Peer {
    pub mail: String,
    pub last_seen: DateTime<Utc>,
    pub timestamp: Option<DateTime<Utc>>,
    pub cert: Option<Cert>,
    pub gossip_timestamp: Option<DateTime<Utc>>,
    pub gossip_cert: Option<Cert>,
    pub prefer: bool,
}

impl<'a> Peer {
    pub fn new(mail: &str, now: DateTime<Utc>, key: Cert, gossip: bool, prefer: bool) -> Self{
        if !gossip {
            Peer {
                mail: mail.to_owned(),
                last_seen: now,
                timestamp: Some(now),
                cert: Some(key),
                gossip_timestamp: None,
                gossip_cert: None,
                prefer,
            }
        } else {
            Peer {
                mail: mail.to_owned(),
                last_seen: now,
                timestamp: None,
                cert: None,
                gossip_timestamp: Some(now),
                gossip_cert: Some(key),
                prefer,
            }
        }
    }
    pub fn get_recipient(&'a self, policy: &'a dyn Policy) -> Result<Recipient> {
        encrypt_key!(self.cert, policy);
        encrypt_key!(self.gossip_cert, policy);
        return Err(anyhow::anyhow!(
                "No Cert found for peer"));
    }
}
