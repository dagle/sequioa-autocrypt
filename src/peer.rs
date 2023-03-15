extern crate sequoia_openpgp as openpgp;
use std::{borrow::Cow, cmp::Ordering};

use crate::{uirecommendation::UIRecommendation, Result};
use chrono::{DateTime, Duration, Utc};
use openpgp::{policy::Policy, serialize::stream::Recipient, Cert};

// we try to to get an encryption key for the specific field
// and return the key if we find one
macro_rules! encrypt_key {
    ($select:expr, $policy:expr) => {
        if let Some(ref cert) = $select {
            if let Some(key) = cert
                .keys()
                .with_policy($policy, None)
                .alive()
                .revoked(false)
                .supported()
                .for_transport_encryption()
                .nth(0)
                .map(|ka| ka.key())
            {
                return Ok(key.into());
            }
        }
    };
}

fn valid_cert(cert: &Option<Cow<Cert>>, policy: &dyn Policy) -> bool {
    if let Some(ref cert) = cert {
        cert.keys()
            .with_policy(policy, None)
            .alive()
            .revoked(false)
            .supported()
            .for_transport_encryption()
            .next()
            .is_some()
    } else {
        false
    }
}

/// Do we and/or peers prefer encrypted emails or cleartext emails.
#[derive(PartialEq, Debug, Copy, Clone, Default)]
pub enum Prefer {
    Mutual,
    #[default]
    Nopreference,
}

impl From<Prefer> for Option<&str> {
    fn from(value: Prefer) -> Self {
        match value {
            Prefer::Mutual => Some("mutual"),
            Prefer::Nopreference => Some("nopreference"),
        }
    }
}

impl Prefer {
    pub(crate) fn encrypt(self) -> bool {
        if self == Self::Mutual {
            return true;
        }
        false
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
    pub fn new(
        mail: &str,
        account: &str,
        now: DateTime<Utc>,
        key: &'a Cert,
        gossip: bool,
        prefer: Prefer,
    ) -> Self {
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

    // Determine if encryption is possible
    pub(crate) fn can_encrypt(&self, policy: &dyn Policy) -> bool {
        valid_cert(&self.cert, policy) || valid_cert(&self.gossip_cert, policy)
    }

    pub(crate) fn preliminary_recommend(&self, policy: &dyn Policy) -> UIRecommendation {
        if !self.can_encrypt(policy) {
            return UIRecommendation::Disable;
        }
        if self.cert.is_some() {
            let stale = Utc::now() + Duration::days(35);
            if stale.cmp(&self.last_seen) == Ordering::Less {
                return UIRecommendation::Discourage;
            }
            return UIRecommendation::Available;
        }
        if self.gossip_cert.is_some() {
            return UIRecommendation::Discourage;
        }
        UIRecommendation::Disable
    }

    pub(crate) fn get_recipient(&'a self, policy: &'a dyn Policy) -> Result<Recipient> {
        encrypt_key!(self.cert, policy);
        encrypt_key!(self.gossip_cert, policy);
        Err(anyhow::anyhow!(
            "Couldn't find any key for transport encryption for peer"
        ))
    }
}
