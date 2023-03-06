// this lib only supports encrypting
// decrypting, verify signs. Signing isn't supported
// besides signing inside an encrypted. This is because
// autocrypt focuses on sending encrypted messages between MUA's
// and not signing clear text messages.

pub mod sq;
pub mod peer;
pub mod store;

pub type Result<T> = sequoia_openpgp::Result<T>;

pub fn canonicalize(email: &str) -> Option<String> {
    let at = email.find("@")?;
    let username = &email[..at];
    let lower = username.to_lowercase();
    let domain = &email[at+1..];
    let idn = idna::domain_to_ascii(domain).ok()?;
    Some(format!("{}@{}", lower, idn))
}
