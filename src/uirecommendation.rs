use std::iter::Sum;

/// UIRecommendation represent whether or not we should encrypt an email.
/// Disable means that we shouldn't try to encrypt because it's likely people
/// won't be able to read it.
/// Discourage means that we have keys for all users to encrypt it but we don't
/// we are not sure they are still valid (we haven't seen them in long while,
/// we got them from gossip etc)
/// Available means all systems are go.
#[derive(Debug, PartialEq)]
pub enum UIRecommendation {
    Disable,
    Discourage,
    Available,
    Encrypt,
}

impl Sum for UIRecommendation {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        for entry in iter {
            if entry == Self::Disable {
                return Self::Disable;
            }
            if entry == Self::Discourage {
                return Self::Discourage;
            }
            if entry != Self::Encrypt {
                return Self::Available;
            }
        }
        Self::Encrypt
    }
}

impl UIRecommendation {
    pub fn encryptable(&self) -> bool {
        if *self == Self::Disable {
            return false;
        }
        true
    }
    pub fn preferable(&self) -> bool {
        if *self == Self::Disable || *self == Self::Discourage {
            return false;
        }
        true
    }
}
