use crate::peer::Prefer;
use sequoia_openpgp::Fingerprint;

#[derive(PartialEq, Debug)]
pub struct Account {
    pub mail: String,
    pub fpr: Fingerprint,

    // If we want to save settings into the database. For some applications
    // you might want configure this in your normal settings rather
    // having it in the database.
    pub prefer: Prefer,
    pub enable: bool,
}

impl Account {
    pub(crate) fn new(mail: &str, fpr: Fingerprint) -> Self {
        Account {
            mail: mail.to_owned(),
            fpr,
            prefer: Prefer::Nopreference,
            enable: false,
        }
    }
}
