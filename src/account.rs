use sequoia_openpgp::Cert;
use crate::peer::Prefer;

#[derive(PartialEq, Debug)]
pub struct Account {
    pub mail: String,
    pub cert: Cert,

    // If we want to save settings into the database. For some applications
    // you might want configure this in your normal settings rather
    // having it in the database.
    pub prefer: Prefer,
    pub enable: bool,
}

impl Account {
    pub(crate) fn new(mail: &str, cert: Cert) -> Self {
        Account { mail: mail.to_owned(), cert, prefer: Prefer::Nopreference, enable: false }
    }
}
