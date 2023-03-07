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
    let at = email.find('@')?;
    let username = &email[..at];
    let lower = username.to_lowercase();
    let domain = &email[at+1..];
    let idn = idna::domain_to_ascii(domain).ok()?;
    Some(format!("{}@{}", lower, idn))
}

#[cfg(test)]
mod tests {
    use super::canonicalize;
    
    #[test]
    fn tolower() {
        let email = "art.vandelay@vandelayindustries.com";
        let result = canonicalize(email).unwrap();
        let compare = "art.vandelay@vandelayindustries.com";

        assert_eq!(result, compare);

        let email = "Art.Vandelay@vandelayindustries.com";
        let result = canonicalize(email).unwrap();
        let compare = "art.vandelay@vandelayindustries.com";

        assert_eq!(result, compare);

        let email = "Art.Vandelay@VandelayIndustries.com";
        let result = canonicalize(email).unwrap();
        let compare = "art.vandelay@vandelayindustries.com";

        assert_eq!(result, compare);
    }

    #[test]
    fn idn() {
        let email = "lemmy@mötorhead.com";
        let result = canonicalize(email).unwrap();
        let compare = "lemmy@xn--mtorhead-n4a.com";

        assert_eq!(result, compare);

        let email = "lemmy.the.mötorhead@mötorhead.com";
        let result = canonicalize(email).unwrap();
        let compare = "lemmy.the.mötorhead@xn--mtorhead-n4a.com";

        assert_eq!(result, compare);
    }

    #[test]
    fn twice() {
        let email = "lemmy.the.mötorhead@mötorhead.com";
        let once = canonicalize(email).unwrap();
        let twice = canonicalize(&once).unwrap();
        let compare = "lemmy.the.mötorhead@xn--mtorhead-n4a.com";

        assert_eq!(twice, compare);
    }
}
