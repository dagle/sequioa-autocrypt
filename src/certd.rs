use std::{borrow::Cow, path::PathBuf};

use sequoia_cert_store::{Store, LazyCert};
use sequoia_openpgp::packet::UserID;
use crate::{store::AutocryptStore, driver::SqlDriver};

pub fn cert_d_path() -> Option<PathBuf> {
    std::env::var_os("PGP_CERT_D").map(Into::into)
        .or_else(|| {
            dirs::data_dir().map(|d| d.join("pgp.cert.d").join("_autocrypt.sqlite"))
        })
}

/// Implement a cert store backend.
/// Using this backend is only safe if the backend is concidered to be in wild mode. Otherwise this
/// will leak certs. Do not enable cert store if you are running with mulitple users.
impl<'a, T: SqlDriver> Store<'a> for AutocryptStore<T> {
    fn lookup_by_cert(&self, kh: &sequoia_openpgp::KeyHandle) -> sequoia_autocrypt::Result<Vec<std::borrow::Cow<sequoia_cert_store::LazyCert<'a>>>> {
        let cert = self.conn.cert(None, kh)?;
        Ok(vec![Cow::Owned(LazyCert::from_cert(cert))])
    }

    fn lookup_by_key(&self, kh: &sequoia_openpgp::KeyHandle) -> sequoia_autocrypt::Result<Vec<std::borrow::Cow<sequoia_cert_store::LazyCert<'a>>>> {

        let certs = self.conn.key(None, kh)?;

        let ret = certs.into_iter().map(|c| Cow::Owned(LazyCert::from_cert(c))).collect();
        Ok(ret)
    }

    /// We ignore the QueryParams and only look at the email address.
    fn select_userid(&self, _query: &sequoia_cert_store::store::UserIDQueryParams, pattern: &str)
        -> sequoia_autocrypt::Result<Vec<std::borrow::Cow<sequoia_cert_store::LazyCert<'a>>>> {

        let uid: UserID = pattern.into();
        let email: &str = &uid.email_normalized()?.ok_or_else(|| anyhow::anyhow!("No email found"))?;

        match self.conn.account(email) {
            Ok(acc) => {

                let cert = self.conn.cert(Some(email), acc.fpr.into())?;
                Ok(vec![Cow::Owned(LazyCert::from_cert(cert))])
            }
            Err(_) => {
                let peer = self.conn.peer(None, email)?;
                let mut certs = vec![];
                if let Some(fpr) = peer.cert_fpr {
                    let cert = self.conn.cert(Some(email), fpr.into())?;
                    certs.push(Cow::Owned(LazyCert::from_cert(cert)));
                }
                if let Some(fpr) = peer.gossip_fpr {
                    let cert = self.conn.cert(Some(email), fpr.into())?;
                    certs.push(Cow::Owned(LazyCert::from_cert(cert)));
                }
                Ok(certs)
            }
        }
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=sequoia_openpgp::Fingerprint> + 'b> {
        self.conn.fingerprints(None)
    }
}
