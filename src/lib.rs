// this lib only supports encrypting
// decrypting, verify signs. Signing isn't supported
// besides signing inside an encrypted. This is because
// autocrypt focuses on sending encrypted messages between MUA's
// and not signing clear text messages.

use sequoia_openpgp::packet::UserID;

pub mod account;
pub mod driver;
pub mod peer;
pub mod sq;
pub mod store;
pub mod uirecommendation;

#[cfg(feature = "rusqlite")]
pub mod rusqlite;

pub type Result<T> = sequoia_openpgp::Result<T>;

pub fn canonicalize(email: &str) -> Result<String> {
    let uid = UserID::from_address(None, None, email)?;
    match uid.email_normalized() {
        Ok(None) => Err(anyhow::anyhow!("Email address couldn't be normalized")),
        Ok(Some(s)) => Ok(s),
        Err(e) => Err(e),
    }
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
